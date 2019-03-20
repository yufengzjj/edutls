import abc
import typing
from enum import IntEnum


class PackableIntEnum(IntEnum):
    @classmethod
    def from_value(cls, value: int):
        for v in cls:
            if v == value:
                return v
        raise Exception(f"bad {cls.__name__}:{value}")

    def pack(self) -> bytes:
        pass

    @classmethod
    def unpack(cls, data: bytes):
        pass


class UInt8Enum(PackableIntEnum):
    def pack(self) -> bytes:
        return self.to_bytes(1, "big")

    @classmethod
    def unpack(cls, data: bytes):
        assert len(data) >= 1, f"not enough bytes to unpack {cls.__name__}"
        value = int.from_bytes(data[:1], "big")
        return cls.from_value(value), data[1:]


class UInt16Enum(PackableIntEnum):
    def pack(self) -> bytes:
        return self.to_bytes(2, "big")

    @classmethod
    def unpack(cls, data: bytes):
        assert len(data) >= 2, f"not enough bytes to unpack {cls.__name__}"
        value = int.from_bytes(data[:2], "big")
        return cls.from_value(value), data[2:]


class NoneType(UInt8Enum):
    none = 0


class Protocol(abc.ABC):
    @abc.abstractmethod
    def pack(self) -> bytes:
        return b""

    @abc.abstractmethod
    def unpack(self, data: bytes) -> bytes:
        pass

    @property
    def type(self) -> PackableIntEnum:
        return NoneType.none


class PackableInt(Protocol):
    def __init__(self, length: int, value: int):
        self.length = length
        self.value = value

    def unpack(self, data: bytes) -> bytes:
        assert len(data) >= self.length, f"not enough bytes to unpack int{self.length}"
        self.value = int.from_bytes(data[:self.length], "big")
        return data[self.length:]

    def pack(self) -> bytes:
        return self.value.to_bytes(self.length, "big")


class ProtocolVersion(PackableInt):
    def __init__(self, version: int):
        super().__init__(2, version)


class Vector(Protocol):
    def __init__(self, length: int, data: typing.Union[bytes, typing.Tuple[Protocol, ...]] = None):
        """
        :type length:n bytes to hold the size of data
        """
        self.length: int = length
        self.data = data

    def pack(self) -> bytes:
        if isinstance(self.data, (bytes, memoryview)):
            self.data: bytes
            return PackableInt(self.length, len(self.data)).pack() + self.data
        elif isinstance(self.data, tuple):
            self.data: typing.Tuple[Protocol, ...]
            data = b"".join((o.pack() for o in self.data))
            return PackableInt(self.length, len(data)).pack() + data
        else:
            assert False, f"not support {type(self.data)} encoding"

    def unpack(self, data: bytes) -> bytes:
        assert len(data) >= self.length, f"no enough bytes to unpack Vector size"
        size: int = int.from_bytes(data[:self.length], "big")
        assert len(data) >= self.length + size, f"no enough bytes to unpack Vector body"
        self.data: bytes = data[self.length:self.length + size]
        return data[self.length + size:]


class switch(object):
    def __init__(self, value):
        self.value = value
        self.falling = False

    def __iter__(self):
        yield self.match
        raise StopIteration

    def match(self, *args):
        if self.falling or not args:
            return True
        elif self.value in args:
            self.falling = True
            return True
        else:
            return False
