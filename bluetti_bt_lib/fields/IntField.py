import struct

from . import DeviceField, FieldName


class IntField(DeviceField):
    def __init__(
        self,
        name: FieldName,
        address: int,
        multiplier: float = 1,
        min: int | None = None,
        max: int | None = None,
    ):
        super().__init__(name, address, 1)
        self.multiplier = multiplier
        self.min = min
        self.max = max

    def parse(self, data: bytes) -> int:
        val = struct.unpack("!h", data)[0]
        if self.multiplier != 1:
            # Adding 0 turns the -0.0 of a negative multiplier into 0.0
            val = round(val * self.multiplier, 2) + 0
        return val

    def in_range(self, value: int) -> bool:
        if self.min is not None and self.min > value:
            return False
        if self.max is not None and self.max < value:
            return False
        return True
