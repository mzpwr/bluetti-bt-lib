import asyncio
import logging
from typing import Callable

from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.exc import BleakError
from bleak_retry_connector import BleakClientWithServiceCache, establish_connection
from cryptography.exceptions import InvalidSignature

from ..const import NOTIFY_UUID, WRITE_UUID
from ..utils.privacy import mac_loggable
from .encryption import AES_BLOCK_SIZE, BluettiEncryption, Message, MessageType


class DeviceConnection:
    """Manages a persistent BLE connection shared between DeviceReader and DeviceWriter.

    Owns the BleakClient and BluettiEncryption session. Handles the ECDH handshake
    once on connect, reassembles fragmented encrypted BLE notifications, and routes
    incoming messages:
    - Handshake messages (plaintext or in-band encrypted) are handled internally.
    - Decrypted Modbus responses are dispatched to the active data_callback.
    """

    def __init__(self, address: str, use_encryption: bool = False) -> None:
        self._address = address
        self._use_encryption = use_encryption
        self._client: BleakClientWithServiceCache | None = None
        self._encryption = BluettiEncryption()
        self._encrypted_buffer = bytearray()
        self._handshake_complete: asyncio.Event | None = None
        self._data_callback: Callable[[bytes], None] | None = None
        self.logger = logging.getLogger(
            f"{__name__}.{mac_loggable(address).replace(':', '_')}"
        )

    @property
    def address(self) -> str:
        return self._address

    @property
    def client(self) -> BleakClientWithServiceCache | None:
        return self._client

    @property
    def encryption(self) -> BluettiEncryption:
        return self._encryption

    @property
    def is_connected(self) -> bool:
        return self._client is not None and self._client.is_connected

    def set_data_callback(self, callback: Callable[[bytes], None]) -> None:
        """Called by DeviceReader before sending a command to receive the response."""
        self._data_callback = callback

    def clear_data_callback(self) -> None:
        """Called by DeviceReader after receiving the response."""
        self._data_callback = None

    def clear_buffer(self) -> None:
        """Clear any partial encrypted fragment buffer before sending a new command."""
        self._encrypted_buffer.clear()

    async def connect(self) -> bool:
        """Scan for device, establish connection, run ECDH handshake if needed."""
        self._encryption.reset()
        self._encrypted_buffer.clear()
        try:
            device = await self._find_device()
            if device is None:
                return False
            self._client = await self._establish_client(device)
            if self._use_encryption:
                # Create event before subscribing so an immediate CHALLENGE cannot race it.
                self._handshake_complete = asyncio.Event()
            await self._subscribe_notifications()
            if self._use_encryption:
                await self._wait_for_handshake()
            self.logger.debug("Connected successfully")
            return True
        except (BleakError, TimeoutError, asyncio.TimeoutError) as err:
            self.logger.warning("Connection failed: %s", err)
            await self.disconnect()
            return False

    async def ensure_connected(self) -> bool:
        """Reconnect if the connection was dropped."""
        if self.is_connected:
            return True
        self.logger.debug("Connection lost, reconnecting")
        return await self.connect()

    async def disconnect(self) -> None:
        """Explicitly close the connection and reset encryption state."""
        await self._stop_notifications()
        await self._disconnect_client()
        self._encryption.reset()
        self._encrypted_buffer.clear()
        self._handshake_complete = None
        self._client = None

    async def _find_device(self) -> BLEDevice | None:
        """Scan BLE for the device by address."""
        self.logger.debug("Scanning for device %s", mac_loggable(self._address))
        device = await BleakScanner.find_device_by_address(self._address, timeout=5)
        if device is None:
            self.logger.error("Device not found: %s", mac_loggable(self._address))
        return device

    async def _establish_client(
        self, device: BLEDevice
    ) -> BleakClientWithServiceCache:
        """Create and connect a BleakClient using bleak_retry_connector."""
        self.logger.debug("Establishing connection")
        return await establish_connection(
            BleakClientWithServiceCache,
            device,
            device.name or "Unknown Device",
            max_attempts=10,
        )

    async def _subscribe_notifications(self) -> None:
        """Register the single notification handler on NOTIFY_UUID."""
        await self._client.start_notify(NOTIFY_UUID, self._on_notification)
        self.logger.debug("Notification handler registered")

    async def _wait_for_handshake(self) -> None:
        """Wait until the ECDH key exchange is complete."""
        if self._handshake_complete is None:
            self._handshake_complete = asyncio.Event()
        self.logger.debug("Waiting for encryption handshake")
        try:
            await asyncio.wait_for(self._handshake_complete.wait(), timeout=12)
        except asyncio.TimeoutError:
            raise TimeoutError("Encryption handshake timed out")
        self.logger.debug("Encryption handshake complete")

    def _calculate_expected_encrypted_length(self, buffer: bytearray) -> int | None:
        """Calculate expected total length of an encrypted message."""
        if len(buffer) < 2:
            return None

        data_len = (buffer[0] << 8) + buffer[1]
        _, iv = self._encryption.getKeyIv()
        header_size = 6 if iv is None else 2
        padded_len = (
            (data_len + AES_BLOCK_SIZE - 1) // AES_BLOCK_SIZE
        ) * AES_BLOCK_SIZE
        return header_size + padded_len

    async def _on_notification(self, _sender: int, data: bytearray) -> None:
        """Route each incoming BLE notification to the right handler."""
        if not self._use_encryption:
            self._dispatch_data(bytes(data))
            return

        message = Message(data)
        if message.is_pre_key_exchange:
            await self._handle_pre_key_message(message)
            return

        await self._handle_encrypted_message(data)

    async def _handle_pre_key_message(self, message: Message) -> None:
        """Handle unencrypted handshake: CHALLENGE and CHALLENGE_ACCEPTED."""
        message.verify_checksum()
        try:
            message_type = message.type
        except ValueError:
            self.logger.warning("Unknown pre-key-exchange message type")
            return

        if message_type == MessageType.CHALLENGE:
            self.logger.debug("Received challenge, sending response")
            response = self._encryption.msg_challenge(message)
            if response is not None and self._client is not None:
                try:
                    await self._client.write_gatt_char(WRITE_UUID, response)
                except BleakError as err:
                    self.logger.warning("Challenge response write failed: %s", err)
        elif message_type == MessageType.CHALLENGE_ACCEPTED:
            self.logger.debug("Challenge accepted, starting key exchange")

    async def _handle_encrypted_message(self, data: bytearray) -> None:
        """Buffer fragmented AES frames, decrypt, and route key exchange or data."""
        if self._encryption.unsecure_aes_key is None:
            self.logger.warning(
                "Received encrypted message before challenge completed"
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

        if decrypted.is_pre_key_exchange:
            await self._handle_encrypted_key_message(decrypted, key)
        else:
            self._dispatch_data(bytes(decrypted.buffer))

    async def _handle_encrypted_key_message(
        self, decrypted: Message, active_key: bytes | None
    ) -> None:
        """Handle encrypted key exchange messages (including in-band CHALLENGE)."""
        decrypted.verify_checksum()
        try:
            message_type = decrypted.type
        except ValueError:
            self.logger.warning("Unknown encrypted key exchange message type")
            return

        if message_type == MessageType.CHALLENGE:
            response = self._encryption.msg_challenge(decrypted)
            if response is not None and self._client is not None:
                try:
                    await self._client.write_gatt_char(
                        WRITE_UUID,
                        self._encryption.aes_encrypt(response, active_key, None),
                    )
                except BleakError as err:
                    self.logger.warning(
                        "In-band challenge response write failed: %s", err
                    )
        elif message_type == MessageType.CHALLENGE_ACCEPTED:
            self.logger.debug("Challenge accepted (encrypted)")
        elif message_type == MessageType.PEER_PUBKEY:
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
            if response is not None and self._client is not None:
                try:
                    await self._client.write_gatt_char(WRITE_UUID, response)
                except BleakError as err:
                    self.logger.warning("Peer pubkey write failed: %s", err)
        elif message_type == MessageType.PUBKEY_ACCEPTED:
            self.logger.debug("Key exchange complete, shared secret established")
            self._encryption.msg_key_accepted(decrypted)
            if self._handshake_complete is not None:
                self._handshake_complete.set()

    def _dispatch_data(self, data: bytes) -> None:
        """Deliver a Modbus response to the active data callback."""
        if self._data_callback is not None:
            self._data_callback(data)
        else:
            self.logger.debug("Received data but no callback is registered")

    async def _stop_notifications(self) -> None:
        if self._client is not None:
            try:
                await self._client.stop_notify(NOTIFY_UUID)
            except Exception:
                pass

    async def _disconnect_client(self) -> None:
        if self._client is not None:
            try:
                await self._client.disconnect()
            except Exception:
                pass
