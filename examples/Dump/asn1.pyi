import io
from builtins import bytes
from builtins import int
from enum import IntEnum
from typing import Any
from typing import Generator
from typing import NamedTuple

from _typeshed import Incomplete

INDEFINITE_FORM: int

class Asn1Enum(IntEnum): ...

class Numbers(Asn1Enum):
    Boolean = 1
    Integer = 2
    BitString = 3
    OctetString = 4
    Null = 5
    ObjectIdentifier = 6
    ObjectDescriptor = 7
    External = 8
    Real = 9
    Enumerated = 10
    EmbeddedPDV = 11
    UTF8String = 12
    RelativeOID = 13
    Time = 14
    Sequence = 16
    Set = 17
    NumericString = 18
    PrintableString = 19
    T61String = 20
    VideotextString = 21
    IA5String = 22
    UTCTime = 23
    GeneralizedTime = 24
    GraphicString = 25
    VisibleString = 26
    GeneralString = 27
    UniversalString = 28
    CharacterString = 29
    UnicodeString = 30
    Date = 31
    TimeOfDay = 32
    DateTime = 33
    Duration = 34
    OIDinternationalized = 35
    RelativeOIDinternationalized = 36

class Types(Asn1Enum):
    Constructed = 32
    Primitive = 0

class Classes(Asn1Enum):
    Universal = 0
    Application = 64
    Context = 128
    Private = 192

class ReadFlags(IntEnum):
    OnlyValue = 0
    WithUnused = 1

class Tag(NamedTuple):
    nr: Incomplete
    typ: Incomplete
    cls: Incomplete

def to_int_2c(values: bytes) -> int: ...
def to_bytes_2c(value: int) -> bytes: ...
def shift_bits_right(values, unused): ...
def is_negative_zero(x): ...
def is_positive_infinity(x): ...
def is_negative_infinity(x): ...
def is_nan(x): ...
def is_iterable(value): ...

class Error(Exception): ...

class Encoder:
    def __init__(self) -> None: ...
    def start(self, stream: io.RawIOBase | None = None) -> None: ...
    def enter(self, nr: int, cls: int | None = None) -> None: ...
    def leave(self) -> None: ...
    def construct(self, nr: int, cls: int | None = None) -> Generator[None, Any, None]: ...
    def write(self, value: Any, nr: int | None = None, typ: int | None = None, cls: int | None = None) -> None: ...
    def output(self) -> bytes: ...

class Decoder:
    def __init__(self) -> None: ...
    def start(self, stream: io.RawIOBase | bytes) -> None: ...
    def peek(self) -> Tag | None: ...
    def read(self, flags: ReadFlags = ...) -> tuple[Tag | None, Any]: ...
    def eof(self) -> bool: ...
    def enter(self) -> None: ...
    def leave(self) -> None: ...
