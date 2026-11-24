import asyncio
import logging
from typing import Any
import async_timeout
from bleak import BleakClient
from bleak.exc import BleakError
from cryptography.exceptions import InvalidSignature

from ..const import NOTIFY_UUID, WRITE_UUID
from ..base_devices import BluettiDevice
from ..utils.privacy import mac_loggable
from .device_connection import DeviceConnection
from .encryption import AES_BLOCK_SIZE, BluettiEncryption, Message, MessageType


class DeviceWriterConfig:
    def __init__(self, timeout: int = 15, use_encryption: bool = False) -> None:
        self.timeout = timeout
        self.use_encryption = use_encryption


class DeviceWriter:
    def __init__(
        self,
        bleak_client: BleakClient | None,
        bluetti_device: BluettiDevice,
        config: DeviceWriterConfig | None = None,
        lock: asyncio.Lock | None = None,
        connection: DeviceConnection | None = None,
    ) -> None:
        self.client = bleak_client
        self.bluetti_device = bluetti_device
        self.config = config if config is not None else DeviceWriterConfig()
        self.polling_lock = lock if lock is not None else asyncio.Lock()
        self.connection = connection
        self._encryption = BluettiEncryption()
        self._encrypted_buffer = bytearray()
        self._handshake_complete: asyncio.Event | None = None

        if connection is not None:
            address = connection.address
        elif bleak_client is not None:
            address = bleak_client.address
        else:
            address = "?"

        self.logger = logging.getLogger(
            f"{__name__}.{mac_loggable(address).replace(':', '_')}"
        )

    async def write(self, field: str, value: Any) -> bool:
        command = self._build_write_command(field, value)
        if command is None:
            return False

        async with self.polling_lock:
            try:
                async with async_timeout.timeout(self.config.timeout):
                    await self._connect_if_needed()
                    command_bytes = await self._prepare_command_bytes(bytes(command))
                    client = self._active_client()
                    if client is None:
                        self.logger.error("No active BLE client for write")
                        return False
                    await client.write_gatt_char(WRITE_UUID, command_bytes)
                    self.logger.debug("Write successful")
                    return True
            except TimeoutError:
                self.logger.warning("Timeout writing to device")
                return False
            except BleakError as err:
                self.logger.warning("Bleak error: %s", err)
                return False
            except Exception as err:
                self.logger.warning("Unknown error: %s", err)
                return False
            finally:
                await self._cleanup()

    def _build_write_command(self, field: str, value: Any) -> Any:
        """Validate field and build the Modbus write command. Returns None if invalid."""
        if field not in [f.name for f in self.bluetti_device.fields]:
            self.logger.error("Field not supported: %s", field)
            return None
        command = self.bluetti_device.build_write_command(field, value)
        if command is None:
            self.logger.error("Field is not writeable: %s", field)
        return command

    def _active_client(self) -> BleakClient | None:
        """Return the BleakClient to use — shared connection or own client."""
        if self.connection is not None:
            return self.connection.client
        return self.client

    async def _connect_if_needed(self) -> None:
        if self.connection is not None:
            if not await self.connection.ensure_connected():
                raise BleakError("Could not connect to device via shared connection")
        elif self.client is not None:
            if not self.client.is_connected:
                self.logger.debug("Connecting to device")
                await self.client.connect()
        else:
            raise BleakError("No BLE client or DeviceConnection provided")

    async def _prepare_command_bytes(self, raw_bytes: bytes) -> bytes:
        """Return command bytes ready to send: plain or AES-encrypted."""
        if not self.config.use_encryption:
            return raw_bytes
        if self.connection is not None:
            return self._encrypt_with_shared_session(raw_bytes)
        await self._complete_encryption_handshake()
        return self._encrypt_with_own_session(raw_bytes)

    def _encrypt_with_shared_session(self, data: bytes) -> bytes:
        """Encrypt using the session key already established by DeviceConnection."""
        enc = self.connection.encryption
        return enc.aes_encrypt(data, enc.secure_aes_key, None)

    def _encrypt_with_own_session(self, data: bytes) -> bytes:
        """Encrypt using the session key established by this writer's own handshake."""
        return self._encryption.aes_encrypt(
            data, self._encryption.secure_aes_key, None
        )

    async def _complete_encryption_handshake(self) -> None:
        """Subscribe to BLE notifications and wait until ECDH key exchange is complete."""
        self._encryption.reset()
        self._encrypted_buffer.clear()
        self._handshake_complete = asyncio.Event()
        await self.client.start_notify(NOTIFY_UUID, self._on_encryption_message)
        self.logger.debug("Waiting for encryption handshake")
        try:
            await asyncio.wait_for(self._handshake_complete.wait(), timeout=12)
        except asyncio.TimeoutError:
            raise TimeoutError("Encryption handshake timed out")
        self.logger.debug("Encryption handshake complete")

    async def _cleanup(self) -> None:
        if self.connection is not None:
            return  # Shared connection outlives this write — do not touch it
        await self._teardown_own_connection()

    async def _teardown_own_connection(self) -> None:
        """Stop notifications, reset encryption, and disconnect own client."""
        if self.config.use_encryption:
            if self.client is not None:
                try:
                    await self.client.stop_notify(NOTIFY_UUID)
                except Exception:
                    pass
            self._encryption.reset()
            self._encrypted_buffer.clear()
        if self.client is not None:
            try:
                await self.client.disconnect()
            except Exception:
                pass

    def _calculate_expected_encrypted_length(self, buffer: bytearray) -> int | None:
        if len(buffer) < 2:
            return None
        data_len = (buffer[0] << 8) + buffer[1]
        _, iv = self._encryption.getKeyIv()
        header_size = 6 if iv is None else 2
        padded_len = (
            (data_len + AES_BLOCK_SIZE - 1) // AES_BLOCK_SIZE
        ) * AES_BLOCK_SIZE
        return header_size + padded_len

    async def _on_encryption_message(self, _sender: int, data: bytearray) -> None:
        """Dispatch each BLE notification to the appropriate handshake handler."""
        message = Message(data)
        if message.is_pre_key_exchange:
            await self._handle_pre_key_message(message)
        else:
            await self._handle_encrypted_handshake_message(data)

    async def _handle_pre_key_message(self, message: Message) -> None:
        """Handle unencrypted handshake messages: challenge and challenge-accepted."""
        message.verify_checksum()
        try:
            message_type = message.type
        except ValueError:
            return
        if message_type == MessageType.CHALLENGE:
            self.logger.debug("Received challenge, sending response")
            response = self._encryption.msg_challenge(message)
            if response is not None and self.client is not None:
                try:
                    await self.client.write_gatt_char(WRITE_UUID, response)
                except BleakError as err:
                    self.logger.warning("Challenge response write failed: %s", err)
        elif message_type == MessageType.CHALLENGE_ACCEPTED:
            self.logger.debug("Challenge accepted, starting key exchange")

    async def _handle_encrypted_handshake_message(self, data: bytearray) -> None:
        """Handle encrypted handshake messages with AES fragment buffering."""
        if self._encryption.unsecure_aes_key is None:
            self.logger.warning(
                "Received encrypted message before challenge was completed"
            )
            return

        self._encrypted_buffer.extend(data)
        expected_len = self._calculate_expected_encrypted_length(self._encrypted_buffer)
        if expected_len is None or len(self._encrypted_buffer) < expected_len:
            return

        complete_message = bytes(self._encrypted_buffer[:expected_len])
        if len(self._encrypted_buffer) > expected_len:
            self._encrypted_buffer = self._encrypted_buffer[expected_len:]
        else:
            self._encrypted_buffer.clear()

        key, iv = self._encryption.getKeyIv()
        try:
            decrypted = Message(
                self._encryption.aes_decrypt(complete_message, key, iv)
            )
        except ValueError as err:
            self.logger.error("Decryption failed: %s", err)
            self._encrypted_buffer.clear()
            return

        if not decrypted.is_pre_key_exchange:
            return

        decrypted.verify_checksum()
        try:
            message_type = decrypted.type
        except ValueError:
            return

        if message_type == MessageType.PEER_PUBKEY:
            self.logger.debug("Received peer public key, sending ours")
            try:
                response = self._encryption.msg_peer_pubkey(decrypted)
            except InvalidSignature:
                self.logger.warning(
                    "Peer pubkey signature rejected, restarting handshake"
                )
                self._encryption.reset()
                self._encrypted_buffer.clear()
                return
            if response is not None and self.client is not None:
                try:
                    await self.client.write_gatt_char(WRITE_UUID, response)
                except BleakError as err:
                    self.logger.warning("Peer pubkey write failed: %s", err)
        elif message_type == MessageType.PUBKEY_ACCEPTED:
            self.logger.debug("Key exchange complete, shared secret established")
            self._encryption.msg_key_accepted(decrypted)
            if self._handshake_complete is not None:
                self._handshake_complete.set()
