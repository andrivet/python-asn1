# -*- coding: utf-8 -*-
#
# This file is part of Python-ASN1. Python-ASN1 is free software that is
# made available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# Python-ASN1 is copyright (c) 2007-2025 by the Python-ASN1 authors. See the
# file "AUTHORS" for a complete overview.

"""
This module provides ASN.1 encoder and decoder.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import collections
import io
import math
import re
from builtins import bytes
from builtins import int
from builtins import range
from builtins import str
from contextlib import contextmanager
from enum import IntEnum
from functools import reduce

__version__ = "3.0.0"

from typing import Any  # noqa: F401
from typing import Generator  # noqa: F401
from typing import List  # noqa: F401
from typing import Tuple  # noqa: F401
from typing import Union  # noqa: F401

INDEFINITE_FORM = -1  # Length that represents an indefinite form


class Asn1Enum(IntEnum):
    def __repr__(self):
        return '<{cls}.{name}: 0x{value:02x}>'.format(
            cls=type(self).__name__,
            name=self.name,
            value=self.value
        )


class Numbers(Asn1Enum):
    Boolean = 0x01
    Integer = 0x02
    BitString = 0x03
    OctetString = 0x04
    Null = 0x05
    ObjectIdentifier = 0x06
    ObjectDescriptor = 0x07
    External = 0x08
    Real = 0x09
    Enumerated = 0x0a
    EmbeddedPDV = 0x0b
    UTF8String = 0x0c
    RelativeOID = 0x0d
    Time = 0x0e
    Sequence = 0x10
    Set = 0x11
    NumericString = 0x12
    PrintableString = 0x13
    T61String = 0x14
    VideotextString = 0x15
    IA5String = 0x16
    UTCTime = 0x17
    GeneralizedTime = 0x18
    GraphicString = 0x19
    VisibleString = 0x1a
    GeneralString = 0x1b
    UniversalString = 0x1c
    CharacterString = 0x1d
    UnicodeString = 0x1e
    Date = 0x1f
    TimeOfDay = 0x20
    DateTime = 0x21
    Duration = 0x22
    OIDinternationalized = 0x23
    RelativeOIDinternationalized = 0x24


class Types(Asn1Enum):
    Constructed = 0x20
    Primitive = 0x00


class Classes(Asn1Enum):
    Universal = 0x00
    Application = 0x40
    Context = 0x80
    Private = 0xc0


class ReadFlags(IntEnum):
    OnlyValue = 0x00
    WithUnused = 0x01


Tag = collections.namedtuple('Tag', 'nr typ cls')
"""
A named tuple to represent ASN.1 tags as returned by `Decoder.peek()` and
`Decoder.read()`.
"""


def to_int_2c(values):  # type: (bytes) -> int
    """Bytes to integer conversion in two's complement."""
    nb_bytes = len(values)
    value = reduce(lambda r, b: (r << 8) | b, values, 0)
    # Negative value?
    if int(values[0]) & 0x80 == 0x80:
        value -= 1 << (nb_bytes * 8)  # two's complement
    return value


def to_bytes_2c(value):  # type: (int) -> bytes
    """Integer to two's complement bytes."""
    if value == 0:
        return b'\x00'

    values = []  # type: List[int]
    if value >= 0:
        # positive
        while value != 0:
            values.append(value & 0xFF)
            value >>= 8
    else:
        # negative
        value = -value
        # two's complement, byte per byte
        while value != 0:
            values.append(((value ^ 0xFF) + 1) & 0xFF)
            value >>= 8
        # Add leading 0xFF bytes if the most significant bit is unset
        if values[len(values)-1] & 0x80 == 0:
            values.append(0xFF)

    values.reverse()
    return bytes(values)


def shift_bits_right(values, unused):  # type (bytes) -> bytes
    if unused == 0:
        return values

    # Shift off unused bits
    remaining = bytearray(values)
    bitmask = (1 << unused) - 1
    removed_bits = 0

    for i, byte in enumerate(remaining):
        remaining[i] = (byte >> unused) | (removed_bits << unused)
        removed_bits = byte & bitmask

    return bytes(remaining)


def is_negative_zero(x):
    return math.copysign(1, x) == -1.0 and x == 0.0


def is_positive_infinity(x):
    return math.isinf(x) and x > 0


def is_negative_infinity(x):
    return math.isinf(x) and x < 0


def is_nan(x):
    return math.isnan(x)


def is_iterable(value):
    try:
        iter(value)
        return True
    except TypeError:
        return False


class Error(Exception):
    """ASN.11 encoding or decoding error."""


class Encoder(object):
    """ASN.1 encoder. Uses DER encoding.

    Args:
        definite (bool): If False (the default), encode constructed types
            with indefinite length. If True, encode constructed types with
            definite length; this may require more memory.
    """

    def __init__(self, definite=False):  # type: (bool) -> None
        """Constructor."""
        self._stream = None                 # type: Union[io.RawIOBase, None]  # Output stream
        self._entered = None                # type Encoder # Sub-encoder for currently entered constructed value
        self._definite = definite           # type bool # If True, generate definite-length output

    def start(self, stream=None):    # type: (Union[io.RawIOBase, None]) -> None
        """
        This method instructs the encoder to start encoding a new ASN.1
        output. This method may be called at any time to reset the encoder,
        and resets the current output (if any).

        Args:
            stream (io.RawIOBase or None): The output stream.
        """
        self._stream = io.BytesIO() if stream is None else stream  # type: ignore

    def enter(self, nr, cls=None):  # type: (int, Union[int, None]) -> None
        """
        This method starts the construction of a constructed type.

        Args:
            nr (int): The desired ASN.1 type. Use ``Numbers`` enumeration.

            cls (int): This optional parameter specifies the class
                of the constructed type. The default class to use is the
                universal class. Use ``Classes`` enumeration.

        Returns:
            None

        Raises:
            `Error`
        """
        if self._stream is None:
            raise Error('Encoder not initialized. Call start() first.')
        if self._entered is not None:
            self._entered.enter(nr, cls)
        else:
            if cls is None:
                cls = Classes.Universal
            self._check_type(nr, Types.Constructed, cls)
            self._emit_tag(nr, Types.Constructed, cls)
            self._entered = Encoder(definite=self._definite)
            if self._definite:
                self._entered.start()
            else:
                self._emit_indefinite_length()
                self._entered.start(stream=self._stream)

    def leave(self):  # type: () -> None
        """
        This method completes the construction of a constructed type and
        writes the encoded representation to the output stream.
        """
        if self._stream is None:
            raise Error('Encoder not initialized. Call start() first.')
        if self._entered is None:
            raise Error('Call to leave() without a corresponding enter() call.')
        if self._entered._entered is not None:
            self._entered.leave()
        else:
            if self._definite:
                sub_bytes = self._entered.output()
                self._emit_length(len(sub_bytes))
                self._write_bytes(sub_bytes)
            else:
                self._emit_eoc()
            self._entered = None

    @contextmanager
    def construct(self, nr, cls=None):  # type: (int, Union[int, None]) -> Generator[None, Any, None]
        """
        This method - context manager calls enter and leave methods,
        for better code mapping.

        Usage:
        ```
        with encoder.construct(asn1.Numbers.Sequence):
            encoder.write(1)
            with encoder.construct(asn1.Numbers.Sequence):
                encoder.write('foo')
                encoder.write('bar')
            encoder.write(2)
        ```
        encoder.output() will result following structure:
        SEQUENCE:
            INTEGER: 1
            SEQUENCE:
                STRING: foo
                STRING: bar
            INTEGER: 2

        Args:
            nr (int): The desired ASN.1 type. Use ``Numbers`` enumeration.

            cls (int): This optional parameter specifies the class
                of the constructed type. The default class to use is the
                universal class. Use ``Classes`` enumeration.

        Returns:
            None

        Raises:
            `Error`

        """
        self.enter(nr, cls)
        yield
        self.leave()

    def write(self, value, nr=None, typ=None, cls=None):  # type: (Any, Union[int, None], Union[int, None], Union[int, None]) -> None
        """
        This method encodes one ASN.1 tag and writes it to the output buffer.

        Note:
            Normally, ``value`` will be the only parameter to this method.
            In this case Python-ASN1 will autodetect the correct ASN.1 type from
            the type of ``value``, and will output the encoded value based on this
            type.

        Args:
            value (any): The value of the ASN.1 tag to write. Python-ASN1 will
                try to autodetect the correct ASN.1 type from the type of
                ``value``.

            nr (int): If the desired ASN.1 type cannot be autodetected or is
                autodetected wrongly, the ``nr`` parameter can be provided to
                specify the ASN.1 type to be used. Use ``Numbers`` enumeration.

            typ (int): This optional parameter can be used to write constructed
                types to the output by setting it to indicate the constructed
                encoding type. In this case, ``value`` must already be valid ASN.1
                encoded data as plain Python bytes. This is not normally how
                constructed types should be encoded though, see `Encoder.enter()`
                and `Encoder.leave()` for the recommended way of doing this.
                Use ``Types`` enumeration.

            cls (int): This parameter can be used to override the class of the
                ``value``. The default class is the universal class.
                Use ``Classes`` enumeration.

        Returns:
            None

        Raises:
            `Error`
        """
        if self._stream is None:
            raise Error('Encoder not initialized. Call start() first.')

        if cls is None:
            cls = Classes.Universal

        if cls != Classes.Universal and nr is None:
            raise Error('Specify a tag number (nr) when using classes Application, Context or Private')

        if self._entered is not None:
            self._entered.write(value, nr, typ, cls)

        else:
            # Constructed
            if nr is None and not isinstance(value, str) and not isinstance(value, bytes) and is_iterable(value):
                nr = Numbers.Sequence
                if typ is None:
                    typ = Types.Constructed
            # Primitive
            elif nr is None:
                if isinstance(value, bool):
                    nr = Numbers.Boolean
                elif isinstance(value, int):
                    nr = Numbers.Integer
                elif isinstance(value, float):
                    nr = Numbers.Real
                elif isinstance(value, str):
                    nr = Numbers.PrintableString
                elif value is None:
                    nr = Numbers.Null
                else:
                    nr = Numbers.OctetString

                if typ is None:
                    typ = Types.Primitive

            if typ is None:
                typ = Types.Primitive

            self._check_type(nr, typ, cls)

            if typ == Types.Primitive:
                encoded = self._encode_value(cls, nr, value)
                self._emit_tag(nr, typ, cls)
                self._emit_length(len(encoded))
                self._write_bytes(encoded)
            else:
                self._emit_sequence(nr, cls, value)

    def output(self):  # type: () -> bytes
        """
        This method returns the encoded ASN.1 data as plain Python ``bytes``.
        This method can be called multiple times, also during encoding.
        In the latter case the data that has been encoded so far is
        returned.

        Note:
            It is an error to call this method if the encoder is still
            constructing a constructed type, i.e. if `Encoder.enter()` has been
            called more times that `Encoder.leave()`.

        Returns:
            bytes: The DER encoded ASN.1 data.

        Raises:
            `Error`
        """
        if self._stream is None:
            raise Error('Encoder not initialized. Call start() first.')
        if not isinstance(self._stream, io.BytesIO):
            raise Error('This method can only be called if the stream is io.BytesIO.')
        return self._stream.getvalue()

    @staticmethod
    def _check_type(nr, typ, cls):  # type: (int, int, int) -> None
        if cls == int(Classes.Universal) and (nr == 0 or nr == 15 or nr >= 37):
            raise Error('ASN1 encoding error: Universal tag number {} is reserved by ASN.1 standard.'.format(nr))

        # Those types shall have a primary encoding
        if (cls == int(Classes.Universal) and typ != int(Types.Primitive) and
            nr in (Numbers.Boolean, Numbers.Integer, Numbers.Enumerated, Numbers.Real,
                   Numbers.Null, Numbers.ObjectIdentifier, Numbers.RelativeOID,
                   Numbers.Time, Numbers.Date, Numbers.TimeOfDay, Numbers.Duration)):
            raise Error('ASN1 encoding error: the Universal tag {} shall have a primitive encoding'.format(nr))

        # Those types shall have a constructed encoding
        if cls == int(Classes.Universal) and nr in (Numbers.Sequence, Numbers.Set) and typ != int(Types.Constructed):
            raise Error('ASN1 encoding error: the Universal tag number {} shall have a constructed encoding'.format(nr))

    def _emit_tag(self, nr, typ, cls):  # type: (int, int, int) -> None
        """Emit a tag."""
        if nr < 31:
            self._emit_tag_short(nr, typ, cls)
        else:
            self._emit_tag_long(nr, typ, cls)

    def _emit_tag_short(self, nr, typ, cls):  # type: (int, int, int) -> None
        """Emit a short (< 31 bytes) tag."""
        assert nr < 31
        self._write_bytes(bytes([nr | typ | cls]))

    def _emit_tag_long(self, nr, typ, cls):  # type: (int, int, int) -> None
        """Emit a long (>= 31 bytes) tag."""
        head = bytes([typ | cls | 0x1f])
        self._write_bytes(head)
        values = [(nr & 0x7f)]
        nr >>= 7
        while nr:
            values.append((nr & 0x7f) | 0x80)
            nr >>= 7
        values.reverse()
        for val in values:
            self._write_bytes(bytes([val]))

    def _emit_length(self, length):  # type: (int) -> None
        """Emit length bytes."""
        if length == INDEFINITE_FORM:
            self._emit_indefinite_length()
        elif length < 128:
            self._emit_length_short(length)
        else:
            self._emit_length_long(length)

    def _emit_length_short(self, length):  # type: (int) -> None
        """Emit the short length form (< 128 octets)."""
        assert length < 128
        self._write_bytes(bytes([length]))

    def _emit_length_long(self, length):  # type: (int) -> None
        """Emit the long length form (>= 128 octets)."""
        values = []
        while length:
            values.append(length & 0xff)
            length >>= 8
        values.reverse()
        # really for correctness as this should not happen anytime soon
        assert len(values) < 127
        head = bytes([0x80 | len(values)])
        self._write_bytes(head)
        for val in values:
            self._write_bytes(bytes([val]))

    def _emit_indefinite_length(self):  # type: () -> None
        if self._definite:
            raise Error('Attempted to emit indefinite length while in definite-length mode')
        self._write_bytes(b'\x80')

    def _emit_eoc(self):  # type: () -> None
        if self._definite:
            raise Error('Attempted to emit end-of-contents tag while in definite-length mode')
        self._write_bytes(b'\x00\x00')

    def _write_bytes(self, s):  # type: (bytes) -> None
        """Emit raw bytes."""
        if self._stream is None:
            raise Error('Encoder not initialized. Call start() first.')
        self._stream.write(s)

    def _encode_value(self, cls, nr, value):  # type: (int, int, Any) -> bytes
        """Encode a value."""
        if cls != Classes.Universal:
            return value

        if nr in (Numbers.Integer, Numbers.Enumerated):
            return self._encode_integer(value)
        if nr in (Numbers.OctetString, Numbers.PrintableString,
                  Numbers.UTF8String, Numbers.IA5String,
                  Numbers.UnicodeString, Numbers.UTCTime,
                  Numbers.GeneralizedTime):
            return self._encode_octet_string(value)
        if nr == Numbers.BitString:
            return self._encode_bit_string(value)
        if nr == Numbers.Boolean:
            return self._encode_boolean(value)
        if nr == Numbers.Null:
            return self._encode_null()
        if nr == Numbers.Real:
            return self._encode_real(value)
        if nr == Numbers.ObjectIdentifier:
            return self._encode_object_identifier(value)

        return value

    @staticmethod
    def _encode_boolean(value):  # type: (bool) -> bytes
        """Encode a boolean."""
        return bytes(b'\xff') if value else bytes(b'\x00')

    @staticmethod
    def _encode_integer(value):  # type: (int) -> bytes
        """Encode an integer."""
        if value < 0:
            value = -value
            negative = True
            limit = 0x80
        else:
            negative = False
            limit = 0x7f
        values = []
        while value > limit:
            values.append(value & 0xff)
            value >>= 8
        values.append(value & 0xff)
        if negative:
            # create two's complement
            for i in range(len(values)):  # Invert bits
                values[i] = 0xff - values[i]
            for i in range(len(values)):  # Add 1
                values[i] += 1
                if values[i] <= 0xff:
                    break
                assert i != len(values) - 1
                values[i] = 0x00
        if negative and values[len(values) - 1] == 0x7f:  # Two's complement corner case
            values.append(0xff)
        values.reverse()
        return bytes(values)

    @staticmethod
    def _encode_real(value):  # type: (float) -> bytes
        """Encode a real number."""
        # 8.5.9
        if is_positive_infinity(value):
            return b'\x40'
        if is_negative_infinity(value):
            return b'\x41'
        if is_nan(value):
            return b'\x42'
        if is_negative_zero(value):
            return b'\x43'

        # 8.5.2
        if value == 0.0:
            return b''

        # 8.5.7
        # Base 2 encoding
        sign = 0 if value >= 0.0 else 1
        mantissa = abs(value)
        exponent = 0
        # 13.3.1
        if int(mantissa) == mantissa:
            # no fractional part
            while mantissa % 2 == 0 and mantissa != 0.0:
                mantissa, exponent = (mantissa / 2, exponent + 1)
        else:
            # fractional number
            while int(mantissa) != mantissa and mantissa != 0.0:
                mantissa, exponent = (mantissa * 2, exponent - 1)

        # Convert exponent to two's complement bytes
        exponent_bytes = to_bytes_2c(exponent)
        nb_exponent_bytes = len(exponent_bytes)
        if nb_exponent_bytes > 255:
            raise Error('Exponent too large')

        first_byte = 0x80           # 8.5.6 a) bit 8 = 1 (binary encoding)
        first_byte |= (sign << 6)   # 8.5.7.1 bit 7 = sign
        first_byte |= 0             # 8.5.7.2 base = 2 (Bits 6-5 = 00)
        first_byte |= 0             # 8.5.7.3 scaling factor F = 0 (Bits 4-3 = 00)
        first_byte |= 0x03 if nb_exponent_bytes >= 3 else nb_exponent_bytes - 1  # 8.5.7.4 - exponent length

        # Convert mantissa to two's complement bytes
        mantissa_bytes = to_bytes_2c(abs(int(mantissa)))

        content = bytearray()
        content.append(first_byte)
        if nb_exponent_bytes > 3:
            content.append(nb_exponent_bytes)
        content.extend(exponent_bytes)
        content.extend(mantissa_bytes)
        return bytes(content)

    @staticmethod
    def _encode_octet_string(value):  # type: (object) -> bytes
        """Encode an octetstring."""
        # Use the primitive encoding
        assert isinstance(value, str) or isinstance(value, bytes)
        if isinstance(value, str):
            return value.encode('utf-8')
        else:
            return value

    @staticmethod
    def _encode_bit_string(value):  # type: (object) -> bytes
        """Encode a bitstring. Assumes no unused bytes."""
        # Use the primitive encoding
        assert isinstance(value, bytes)
        return b'\x00' + value

    @staticmethod
    def _encode_null():  # type: () -> bytes
        """Encode a Null value."""
        return bytes(b'')

    _re_oid = re.compile(r'^[0-9]+(\.[0-9]+)+$')

    def _encode_object_identifier(self, oid):  # type: (str) -> bytes
        """Encode an object identifier."""
        if not self._re_oid.match(oid):
            raise Error('Illegal object identifier')
        cmps = list(map(int, oid.split('.')))
        if (cmps[0] <= 1 and cmps[1] > 39) or cmps[0] > 2:
            raise Error('Illegal object identifier')
        cmps = [40 * cmps[0] + cmps[1]] + cmps[2:]
        cmps.reverse()
        result = []
        for cmp_data in cmps:
            result.append(cmp_data & 0x7f)
            while cmp_data > 0x7f:
                cmp_data >>= 7
                result.append(0x80 | (cmp_data & 0x7f))
        result.reverse()
        return bytes(result)

    def _emit_sequence(self, nr, cls, value):  # type: (int, int, List) -> bytes
        if not is_iterable(value):
            raise Error('value must be an iterable')

        self.enter(nr, cls)
        for item in iter(value):
            self.write(item)
        self.leave()


class Decoder(object):
    """ASN.1 decoder. Understands BER (and DER which is a subset)."""

    def __init__(self):  # type: () -> None
        """Constructor."""
        self._stream = None     # type: Union[io.RawIOBase, io.BufferedIOBase, None]  # Input stream
        self._byte = bytes()    # type: bytes # Cached byte (to be able to implement eof)
        self._position = 0      # type: int # Due to caching, tell does not give the right position
        self._tag = None        # type: Union[Tag, None] # Cached Tag (to be able to implement peek)
        self._levels = 0        # type: int # Number of recursive calls
        self._ends = []         # type: List[int] # End of the current element (or INDEFINITE_FORM) for enter / leave

    def start(self, stream):  # type: (Union[io.RawIOBase, bytes]) -> None
        """
        This method instructs the decoder to start decoding an ASN.1 input.
        This method may be called at any time to start a new decoding job.
        If this method is called while currently decoding another input, that
        decoding context is discarded.

        Note:
            It is not necessary to specify the encoding because the decoder
            assumes the input is in BER or DER format.

        Args:
            stream (bytes or io.RawIOBase): ASN.1 input, in BER or DER format, to be decoded.

        Returns:
            None

        Raises:
            `Error`
        """
        if not isinstance(stream, bytes) and not isinstance(stream, io.RawIOBase) and not isinstance(stream, io.BufferedIOBase):
            raise Error('Expecting bytes or a subclass of io.RawIOBase.')

        self._stream = io.BytesIO(stream) if isinstance(stream, bytes) else stream  # type: ignore
        self._tag = None
        self._byte = bytes()
        self._position = 0
        self._levels = 0
        self._ends = []

    def peek(self):  # type: () -> Union[Tag, None]
        """
        This method returns the current ASN.1 tag (i.e. the tag that a
        subsequent `Decoder.read()` call would return) without updating the
        decoding offset. In case no more data is available from the input,
        this method returns ``None`` to signal end-of-file.

        This method is useful if you don't know whether the next tag will be a
        primitive or a constructed tag. Depending on the return value of `peek`,
        you would decide to either issue a `Decoder.read()` in case of a primitive
        type, or an `Decoder.enter()` in case of a constructed type.

        Note:
            Because this method does not advance the current offset in the input,
            calling it multiple times in a row will return the same value for all
            calls.

        Returns:
            `Tag`: The current ASN.1 tag.

        Raises:
            `Error`
        """
        if self._stream is None:
            raise Error('No input selected. Call start() first.')
        if self._tag is not None:
            return self._tag
        if self.eof():
            return None
        end = self._ends[-1] if len(self._ends) > 0 else None
        if end is not None and end != INDEFINITE_FORM and self._get_current_position() >= end:
            return None
        self._tag = self._decode_tag()
        if end == INDEFINITE_FORM and self._tag == (0, 0, 0):
            return None
        return self._tag

    def read(self, flags=ReadFlags.OnlyValue):  # type: (ReadFlags) -> Tuple[Union[Tag, None], Any]
        """
        This method decodes one ASN.1 tag from the input and returns it as a
        ``(tag, value)`` tuple. ``tag`` is a 3-tuple ``(nr, typ, cls)``,
        while ``value`` is a Python object representing the ASN.1 value.
        The number of unused bits can be requested in the ``flags`` parameter.
        When ``ReadFlags.OnlyValue`` is specified, the method the tuple ``(tag, (value, unused))``.
        ``unused`` is the number of unused bits removed from the value.
        The offset in the input is increased so that the next `Decoder.read()` call will return the next tag.
        In case no more data is available from the input, this method returns ``None``
        to signal end-of-file.

        Args:
            flags (asn1.DecoderFlags): Return only the value or the value and the number of unused bits as a tuple.

        Returns:
            `Tag`, value: The current ASN.1 tag, its value and the
            number of unused bits if requested in `start`.

        Raises:
            `Error`
        """
        if self._stream is None:
            raise Error('No input selected. Call start() first.')
        tag = self.peek()
        self._tag = None
        if tag is None:
            return None, None
        length = self._decode_length(tag.typ)
        value = self._decode_value(tag.cls, tag.typ, tag.nr, length, flags)
        return tag, value

    def eof(self):  # type: () -> bool
        """
        Return True if we are at the end of input.

        Returns:
            bool: True if all input has been decoded, and False otherwise.
        """
        if self._stream is None:
            return True
        if len(self._byte) != 0:
            return False

        position = self._position
        self._byte = bytes(self._stream.read(1))
        self._position = position
        return len(self._byte) == 0

    def enter(self):  # type: () -> None
        """
        This method enters the constructed type that is at the current
        decoding offset.

        Note:
            It is an error to call `Decoder.enter()` if the to be decoded ASN.1 tag
            is not of a constructed type.
            It is no more necessary to call this method. It is kept only for compatibility
            with previous versions of the library.

        Returns:
            None
        """
        if self._stream is None:
            raise Error('No input selected. Call start() first.')
        tag = self.peek()
        if tag is None:
            return
        if tag.typ != Types.Constructed:
            raise Error('Cannot enter a primitive tag.')
        length = self._decode_length(tag.typ)
        self._tag = None
        self._ends.append(self._get_current_position() + length)

    def leave(self):  # type: () -> None
        """
        This method leaves the last constructed type that was
        `Decoder.enter()`-ed.

        Note:
            It is an error to call `Decoder.leave()` if the current ASN.1 tag
            is not of a constructed type.
            It is no more necessary to call this method. It is kept only for compatibility
            with previous versions of the library.

        Returns:
            None
        """
        if self._stream is None:
            raise Error('No input selected. Call start() first.')
        if len(self._ends) <= 0:
            raise Error('Call to leave() without a corresponding enter() call.')
        self._tag = None
        self._ends.pop()

    def _get_current_position(self):  # type: () -> int
        return 0 if self._stream is None else self._position

    def _read_byte(self):  # type: () -> int
        """Return the next input byte, or raise an error on end-of-input."""
        if self._stream is None:
            raise Error('No input selected. Call start() first.')

        if len(self._byte) != 0:
            b = self._byte
            self._byte = bytes()
            self._position += 1
            return b[0]

        data = bytes(self._stream.read(1))
        if len(data) <= 0:
            raise Error('ASN1 decoding error: premature end of input.')
        self._position += 1
        return data[0]

    def _read_bytes(self, count):  # type: (int) -> bytes
        """Return the next ``count`` bytes of input. Raise error on end-of-input."""
        assert count >= 0
        if count == 0:
            return b''
        if self._stream is None:
            raise Error('No input selected. Call start() first.')

        data = b''
        c = count
        if len(self._byte) != 0:
            data = self._byte
            self._byte = bytes()
            c = count - 1

        data += bytes(self._stream.read(c))
        assert len(data) <= count
        if len(data) < count:
            raise Error('ASN1 decoding error: premature end of input.')
        self._position += count
        return data

    def _decode_tag(self):  # type: () -> Tag
        """Read a tag from the input."""
        byte = self._read_byte()
        # 8.1.2.2
        cls = byte & 0xc0  # a)
        typ = byte & 0x20  # b)
        nr = byte & 0x1f   # c)
        if nr == 0x1f:  # 8.1.2.4.1 - Long form of tag encoding
            # 8.1.2.4.2
            nr = 0
            for byte in iter(self._read_byte, None):
                nr = (nr << 7) | (byte & 0x7f)
                if not byte & 0x80:
                    break
            if nr > 0x7FFFFFFFFFFFFFFF:
                raise Error('ASN1 decoding error: tag number is to big (0x{:0X}).'.format(nr))

        cls = Classes(cls)
        typ = Types(typ)

        if cls == Classes.Universal:
            try:
                nr = Numbers(nr)
            except ValueError:
                pass
        return Tag(nr=nr, typ=typ, cls=cls)

    def _decode_length(self, typ):  # type: (int) -> int
        """Read a length from the input. Returns -1 in case of an indefinite form."""
        byte = self._read_byte()
        # 8.1.3.5 - long form
        if byte & 0x80:   # a)
            count = byte & 0x7f  # b)
            if count == 0x7f:  # c)
                raise Error('ASN1 decoding error: invalid length')
            # 8.1.3.6 - indefinite form
            if count == 0:  # 8.1.3.6.1
                # 8.1.3.2 a)
                if typ == Types.Primitive:
                    raise Error('ASN1 decoding error: a primitive type should use the definite form')
                return INDEFINITE_FORM  # indefinite form
            bytes_data = self._read_bytes(count)
            length = reduce(lambda r, b: r << 8 | b, bytes_data, 0)
        else:
            # 8.1.3.4 - short form
            length = byte
        return length

    def _decode_value(self, cls, typ, nr, length, flags):  # type: (int, int, int, int, ReadFlags) -> Any
        """Read a value from the input. length is -1 in case of an indefinite form."""
        # A primitive type shall have a definite form
        if typ == Types.Primitive and length == INDEFINITE_FORM:
            raise Error('ASN1 decoding error: the primitive type (cls: {}, nr: {}) should use the definite form'.format(cls, nr))

        if cls == Classes.Universal and (nr == 0 or nr == 15 or nr >= 37):
            raise Error('ASN1 decoding error: Universal tag number {} is reserved by ASN.1 standard.'.format(nr))

        # Those types shall have a primary encoding
        if cls == Classes.Universal and nr in (Numbers.Boolean, Numbers.Integer, Numbers.Enumerated, Numbers.Real,
                                               Numbers.Null, Numbers.ObjectIdentifier, Numbers.RelativeOID,
                                               Numbers.Time, Numbers.Date, Numbers.TimeOfDay, Numbers.Duration) and typ != Types.Primitive:
            raise Error('ASN1 decoding error: the Universal tag {} shall have a primitive encoding'.format(nr))

        # Those types shall have a constructed encoding
        if cls == Classes.Universal and nr in (Numbers.Sequence, Numbers.Set) and typ != Types.Constructed:
            raise Error('ASN1 decoding error: the Universal tag number {} shall have a constructed encoding'.format(nr))

        if cls != Classes.Universal:
            if typ == Types.Primitive:
                return self._decode_bytes(typ, nr, length)
            else:
                return self._decode_sequence(length)

        # Primitive encoding
        if nr == Numbers.Boolean:
            return self._decode_boolean(length)
        if nr in (Numbers.Integer, Numbers.Enumerated):
            return self._decode_integer(length)
        if nr == Numbers.Null:
            return self._decode_null(length)
        if nr == Numbers.Real:
            return self._decode_real(length)
        if nr == Numbers.ObjectIdentifier:
            return self._decode_object_identifier(length)

        # Primitive or Constructed encoding
        if nr == Numbers.OctetString:
            return self._decode_octet_string(typ, length)
        if nr in (Numbers.PrintableString, Numbers.IA5String,
                  Numbers.UTF8String, Numbers.UTCTime,
                  Numbers.GeneralizedTime):
            return self._decode_printable_string(typ, nr, length)
        if nr == Numbers.BitString:
            value, unused = self._decode_bitstring(typ, length, flags)
            if flags & ReadFlags.WithUnused:
                return value, unused
            return value

        if typ == Types.Primitive:
            return self._decode_bytes(typ, nr, length)
        return self._decode_sequence(length)

    @staticmethod
    def _check_length(actual_length, expected_length):  # type: (int, int) -> None
        if actual_length == INDEFINITE_FORM:
            raise Error('ASN1 decoding error: the encoding of primitive type shall be definite')
        if expected_length != actual_length:
            raise Error('ASN1 decoding error: the encoding shall consist of {} byte{}.'.format(
                expected_length, '' if expected_length == 1 else 's'))

    def _decode_boolean(self, length):  # type: (int) -> bool
        """Decode a boolean value."""
        self._check_length(length, 1)
        content = self._read_bytes(1)
        return content[0] != 0

    def _decode_integer(self, length):  # type: (int) -> int
        """Decode an integer value."""
        content = self._read_bytes(length)
        # 8.3.2
        if len(content) > 1 and ((content[0] == 0xff and content[1] & 0x80 == 0x80) or (content[0] == 0x00 and content[1] & 0x80 == 0x00)):
            raise Error('ASN1 decoding error: malformed integer')
        return to_int_2c(content)

    def _decode_real(self, length):  # type: (int) -> float
        """Decode a real value."""
        # 8.5.2
        if length == 0:
            return +0.0
        content = self._read_bytes(length)
        info = content[0]
        # 8.5.6
        if (info & 0xC0) == 0x00:
            return self._decode_real_decimal(content)
        if (info & 0xC0) == 0x40:
            return self._decode_real_special(int(content[0]))
        return self._decode_real_binary(content)

    @staticmethod
    def _decode_real_binary(content):  # type: (bytes) -> float
        # 8.5.7
        info = content[0]
        # 8.5.7.1
        sign = -1 if (info & 0x40) == 0x40 else 1

        # 8.5.7.2
        base_bits = (info & 0x30) >> 4
        if base_bits == 0x03:
            raise Error('ASN1 decoding error: reserved value for the base')
        base = 2 if base_bits == 0x00 else 8 if base_bits == 0x01 else 16

        # 8.5.7.3
        scaling = (info & 0x0C) >> 2
        # 8.5.7.4
        exponent, used = Decoder._decode_real_binary_exponent(content)

        # Arbitrary limit to avoid consuming all the memory
        if exponent > 2**30:
            raise Error('ASN1 decoding error: exponent too large ({}).'.format(exponent))

        # 8.5.7.5
        n = reduce(lambda r, b: r << 8 | b, content[used + 1:], 0)

        # 8.5.7
        mantissa = sign * n * pow(2, scaling)

        value = mantissa * pow(base, exponent)
        if value == 0. and mantissa != 0:
            raise Error('ASN1 decoding error: Exponent ({}), mantissa ({}) or factor ({}) too big.'.format(exponent, mantissa, scaling))
        if value == 0:
            raise Error('ASN1 decoding error: invalid encoding for +0.')
        return float(value)  # Always as a float

    @staticmethod
    def _decode_real_binary_exponent(values):  # type: (bytes) -> Tuple[int, int]
        # 8.5.7.4
        info = values[0]
        exponent_fmt = (info & 0x03)
        if exponent_fmt == 0x00:
            return to_int_2c(values[1:2]), 1  # a)
        if exponent_fmt == 0x01:
            return to_int_2c(values[1:3]), 2  # b)
        if exponent_fmt == 0x02:
            return to_int_2c(values[1:4]), 3  # c)
        # d)
        nb_bytes = values[1]
        if nb_bytes == 0:
            raise Error('ASN1 decoding error: zero byte count for the exponent')
        if nb_bytes > 1 and ((values[1] == 0xFF and values[2] & 0x80 == 0x80) or
                             (values[1] == 0x00 and values[2] & 0x80 == 0x00)):
            raise Error('ASN1 decoding error: exponent has invalid 9 first bits')
        exponent = to_int_2c(values[2:nb_bytes+1])
        return exponent, nb_bytes + 1

    @staticmethod
    def _decode_real_decimal(bytes_data):  # type: (bytes) -> float
        """Decode a real value in decimal format."""
        # 8.5.8
        info = bytes_data[0]
        nr = info & 0x3F
        if nr in (0x01, 0x02, 0x03):
            value = float(bytes_data[1:])
            if value == 0:
                raise Error('ASN1 decoding error: invalid encoding for +0 or -0.')
            return value
        raise Error('ASN1 decoding error: invalid decimal number representation (NR)')

    @staticmethod
    def _decode_real_special(value):  # type: (int) -> float
        """Decode a real special value."""
        if value == 0x40:
            return float('inf')
        if value == 0x41:
            return float('-inf')
        if value == 0x42:
            return float('nan')
        if value == 0x43:
            return -0.0
        raise Error('ASN1 decoding error: invalid special value')

    def _decode_null(self, length):  # type: (int) -> Any
        """Decode a Null value."""
        self._check_length(length, 0)
        return None

    def _decode_object_identifier(self, length):  # type: (int) -> str
        """Decode an object identifier."""
        # 8.19.2
        if length < 1:
            raise Error('ASN1 decoding error: the encoding of an OID value should have at least one byte.')

        content = self._read_bytes(length)
        sub_identifiers = []
        value = 0
        for b in content:
            if value == 0 and b == 0x80:
                raise Error('ASN1 decoding error: the first byte of the encoding of an OID value should not be 0x80.')
            value = (value << 7) | (b & 0x7f)
            if b & 0x80 == 0x00:  # Last byte?
                sub_identifiers.append(value)
                value = 0

        if len(sub_identifiers) == 0:
            raise Error('ASN1 decoding error: no sub-identifiers found.')

        # 8.19.4
        if sub_identifiers[0] // 40 <= 1:
            sid1 = sub_identifiers[0] // 40
            sid2 = sub_identifiers[0] % 40
            sids = [sid1, sid2] + sub_identifiers[1:]
        else:
            sids = [2, sub_identifiers[0] - 80] + sub_identifiers[1:]
        return '.'.join([str(sid) for sid in sids])

    def _is_eoc(self):  # type: () -> bool
        tag = self.peek()
        if tag != (0, Types.Primitive, Classes.Universal):
            return False
        length = self._decode_length(tag.typ)
        if length != 0:
            raise Error('ASN1 decoding error: invalid EOC encoding length')
        self._tag = None
        return True

    def _decode_bitstring(self, typ, length, flags):  # type: (int, int, ReadFlags) -> Tuple[bytes, int]
        """Decode a bitstring."""
        data, unused = self._decode_bytes_constructed(Numbers.BitString, length, flags) \
            if typ == Types.Constructed else self._decode_bitstring_primitive(length)
        if self._levels == 0:
            data = shift_bits_right(data, unused)
        return data, unused

    def _decode_bitstring_primitive(self, length):  # type: (int) -> Tuple[bytes, int]
        # Primitive
        # 8.6.2
        if length == 0:
            raise Error('ASN1 decoding error: the initial byte is missing.')

        content = self._read_bytes(length)
        # 8.6.2.2
        num_unused_bits = content[0]
        if not (0 <= num_unused_bits <= 7):
            raise Error('ASN1 decoding error: invalid number of unused bits.')

        return content[1:], num_unused_bits

    def _decode_bytes_constructed(self, nr, length, flags):   # type: (int, int, ReadFlags) -> Tuple[bytes, int]
        if length == INDEFINITE_FORM:
            return self._decode_bytes_indefinite(nr, flags)
        else:
            return self._decode_bytes_definite(nr, length, flags)

    def _decode_bytes_indefinite(self, nr, flags):  # type: (int, ReadFlags) -> Tuple[bytes, int]
        self._levels += 1
        value = b''
        unused = 0
        while not self._is_eoc():
            if unused > 0:
                raise Error('ASN1 decoding error: unused bits shall be 0 unless it is the last segment')
            segment_value, segment_unused = self._decode_bytes_segment(nr, flags)
            value += segment_value
            unused = segment_unused
        self._levels -= 1
        return value, unused

    def _decode_bytes_segment(self, nr, flags):  # type: (int, ReadFlags) -> Tuple[bytes, int]
        tag = self.peek()
        if tag is None:
            raise Error("ASN1 decoding error: premature end of input.")
        if nr != 0 and (tag.nr != nr or tag.cls != Classes.Universal):
            raise Error(
                'ASN1 decoding error: invalid tag (cls={}, nr={}) in a constructed type.'.format(tag.cls, tag.nr))
        tag, value = self.read(flags)
        unused = 0
        if flags & ReadFlags.WithUnused:
            value, unused = value
        if not isinstance(value, bytes):
            raise Error('ASN1 decoding error: bytes were expected instead of the type {}'.format(type(value)))
        return value, unused

    def _decode_bytes_definite(self, nr, length, flags):  # type: (int, int, ReadFlags) -> Tuple[bytes, int]
        self._levels += 1
        value = b''
        unused = 0
        start_position = self._get_current_position()
        while self._get_current_position() - start_position < length:
            if unused > 0:
                raise Error('ASN1 decoding error: unused bits shall be 0 unless it is the last segment')
            segment_value, segment_unused = self._decode_bytes_segment(nr, flags)
            value += segment_value
            unused = segment_unused

        if self._get_current_position() - start_position != length:
            raise Error('ASN1 decoding error: invalid length ({})'.format(length))

        self._levels -= 1
        return value, unused

    def _decode_octet_string(self, typ, length):  # type: (int, int) -> bytes
        """Decode an octet string."""
        if typ == Types.Primitive:
            return self._read_bytes(length)
        value, unused = self._decode_bytes_constructed(Numbers.OctetString, length, ReadFlags.OnlyValue)
        assert unused == 0
        return value

    def _decode_bytes(self, typ, nr, length):  # type: (int, int, int) -> bytes
        """Decode a string."""
        if typ == Types.Primitive:
            return self._read_bytes(length)
        value, unused = self._decode_bytes_constructed(nr, length, ReadFlags.OnlyValue)
        assert unused == 0
        return value

    def _decode_printable_string(self, typ, nr, length):  # type: (int, int, int) -> str
        """Decode a printable string."""
        return self._decode_bytes(typ, nr, length).decode('utf-8')

    def _decode_sequence(self, length):  # type: (int) -> List[Any]
        """Decode a sequence."""
        if length == INDEFINITE_FORM:
            return self._decode_sequence_indefinite()
        else:
            return self._decode_constructed_definite(length)

    def _decode_sequence_indefinite(self):  # type: () -> List[Any]
        self._levels += 1
        value = []
        while not self._is_eoc():
            segment_value = self._decode_sequence_segment()
            value.append(segment_value)
        self._levels -= 1
        return value

    def _decode_sequence_segment(self):  # type: () -> Any
        tag = self.peek()
        if tag is None:
            raise Error('ASN1 decoding error: end-of-content not found.')
        tag, value = self.read()
        return value

    def _decode_constructed_definite(self, length):  # type: (int) -> List[Any]
        self._levels += 1
        value = []
        start_position = self._get_current_position()
        while self._get_current_position() - start_position < length:
            segment_value = self._decode_sequence_segment()
            value.append(segment_value)
        if self._get_current_position() - start_position != length:
            raise Error('ASN1 decoding error: invalid length ({})'.format(length))
        self._levels -= 1
        return value
