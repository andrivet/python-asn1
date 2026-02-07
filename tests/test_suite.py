# -*- coding: utf-8 -*-
#
# This file is part of Python-ASN1. Python-ASN1 is free software that is
# made available under the MIT license. Consult the file "LICENSE" that
# is distributed together with this file for the exact licensing terms.
#
# Python-ASN1 is copyright (c) 2007-2026 by the Python-ASN1 authors. See the
# file "AUTHORS" for a complete overview.

# Based on Free ASN.1:2008 compliance suite
# https://www.strozhevsky.com/free_docs/free_asn1_testsuite_descr.pdf

import os
from builtins import bytes
from builtins import int
from builtins import str
from typing import Any
from typing import Generator

import pytest

import asn1


@pytest.fixture
def decode_ber(filename, request):  # type: (str, Any) -> Generator[asn1.Decoder, Any, None]
    test_dir = os.path.join(os.path.dirname(request.module.__file__), 'testsuite')
    pathname = os.path.join(test_dir, filename)
    with open(pathname, "rb") as f:
        dec = asn1.Decoder()
        dec.start(f.read())
        yield dec


class TestSuiteCommonBlocks:
    @pytest.mark.parametrize('filename', ['tc1.ber'])
    def test_case_1(self, decode_ber):
        """
        Too big tag number.
        Decoder must show tag number in hexadecimal format.
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.peek()
        assert "0x3FFFFFFFFFFFFFFFFF" in str(e.value)

    @pytest.mark.parametrize('filename', ['tc2.ber'])
    def test_case_2(self, decode_ber):
        """
        Never-ending tag number (non-finished encoding of tag number).
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read()
        assert "premature end of input" in str(e.value)

    @pytest.mark.parametrize('filename', ['tc3.ber'])
    def test_case_3(self, decode_ber):
        """
        Absence of standard length block.
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read()
        assert "premature end of input" in str(e.value)

    @pytest.mark.parametrize('filename', ['tc4.ber'])
    def test_case_4(self, decode_ber):
        """
        0xFF value as standard length block".
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read()
        assert "invalid length" in str(e.value)

    @pytest.mark.parametrize('filename', ['tc5.ber'])
    def test_case_5(self, decode_ber):
        """
        Unnecessary usage of long length form (length value is less than 127, but long form of length encoding is used).
        """
        tag, value = decode_ber.read()
        assert tag == (0x7FFFFFFFFFFFFFFF, asn1.Types.Primitive, asn1.Classes.Context)


class TestSuiteReal:
    @pytest.mark.parametrize('filename', ['tc6.ber'])
    def test_case_6(self, decode_ber):
        """
        Encoding of "+0" REAL value with more than 0 octets in value block.
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read()
        assert "invalid encoding for +0" in str(e.value)

    @pytest.mark.parametrize('filename', ['tc7.ber'])
    def test_case_7(self, decode_ber):
        """
        Encoding of "-0" REAL value in common way (not as a "special value").
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read()
        assert "invalid encoding for +0 or -0" in str(e.value)

    @pytest.mark.parametrize('filename', ['tc8.ber'])
    def test_case_8(self, decode_ber):
        """
        Encoding "special value", but value block has length more than 1.
        """
        tag, value = decode_ber.read()
        assert tag == (asn1.Numbers.Real, asn1.Types.Primitive, asn1.Classes.Universal)
        assert value == float('-inf')

    @pytest.mark.parametrize('filename', ['tc9.ber'])
    def test_case_9(self, decode_ber):
        """
        Bits 6 and 5 of information octet for REAL are equal to 11 base 2.
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read()
        assert "reserved value for the base" in str(e.value)

    @pytest.mark.parametrize('filename', ['tc10.ber'])
    def test_case_10(self, decode_ber):
        """
        Needlessly long encoding of exponent block for REAL type.
        """
        tag, value = decode_ber.read()
        assert tag == (asn1.Numbers.Real, asn1.Types.Primitive, asn1.Classes.Universal)
        assert value == 2.5

    @pytest.mark.parametrize('filename', ['tc11.ber'])
    def test_case_11(self, decode_ber):
        """
        Incorrect NR form.
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read()
        assert "invalid decimal number representation" in str(e.value)

    @pytest.mark.parametrize('filename', ['tc12.ber'])
    def test_case_12(self, decode_ber):
        """
        Encoding of "special value" not from ASN.1 standard.
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read()
        assert "invalid special value" in str(e.value)

    @pytest.mark.parametrize('filename', ['tc13.ber'])
    def test_case_13(self, decode_ber):
        """
        Absence of mantissa block.
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read()
        assert "premature end of input" in str(e.value)

    @pytest.mark.parametrize('filename', ['tc14.ber'])
    def test_case_14(self, decode_ber):
        """
        Absence of exponent and mantissa block.
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read()
        assert "premature end of input" in str(e.value)

    @pytest.mark.parametrize('filename', ['tc15.ber'])
    def test_case_15(self, decode_ber):
        """
        Too big value of exponent.
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read()
        assert "exponent too large" in str(e.value)

    @pytest.mark.parametrize('filename', ['tc16.ber'])
    def test_case_16(self, decode_ber):
        """
        Too big value of mantissa.
        Note: Python is able to handle very big numbers so no error.
        """
        tag, value = decode_ber.read()
        assert tag == (asn1.Numbers.Real, asn1.Types.Primitive, asn1.Classes.Universal)

    @pytest.mark.parametrize('filename', ['tc17.ber'])
    def test_case_17(self, decode_ber):
        """
        Too big values for exponent and mantissa + using of "scaling factor" value.
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read()
        assert "too big" in str(e.value)


class TestSuiteInteger:
    @pytest.mark.parametrize('filename', ['tc18.ber'])
    def test_case_18(self, decode_ber):
        """
        Needlessly long encoding for INTEGER value.
        Note: In fact, it is malformed. From the standard:
        "If the contents octets of an integer value encoding consist of more than one octet, then the bits of the first
        octet and bit 8 of the second octet ... shall not all be one"
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read()
        assert "malformed integer" in str(e.value)

    @pytest.mark.parametrize('filename', ['tc19.ber'])
    def test_case_19(self, decode_ber):
        """
        Never-ending encoding for INTEGER type (non-finished encoding).
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read()
        assert "premature end of input" in str(e.value)

    @pytest.mark.parametrize('filename', ['tc20.ber'])
    def test_case_20(self, decode_ber):
        """
        Too big INTEGER number encoded.
        Note: Python is able to handle very big numbers so no error.
        """
        tag, value = decode_ber.read()
        assert tag == (asn1.Numbers.Integer, asn1.Types.Primitive, asn1.Classes.Universal)
        assert isinstance(value, int)
        assert value == -2361182958856022458111

class TestSuiteObjectIdentifier:
    @pytest.mark.parametrize('filename', ['tc21.ber'])
    def test_case_21(self, decode_ber):
        """
        Needlessly long format of SID encoding.
        Note: The standard says he subidentifier shall be encoded in the fewest possible octets, that is, the leading
        octet of the subidentifier shall not have the value 80 base 16.
        So this implementation raises an exception.
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read()
        assert "should not be 0x80" in str(e.value)

    @pytest.mark.parametrize('filename', ['tc22.ber'])
    def test_case_22(self, decode_ber):
        """
        Too big value for SID.
        Note: Python is able to handle very big numbers so no error.
        """
        tag, value = decode_ber.read()
        assert tag == (asn1.Numbers.ObjectIdentifier, asn1.Types.Primitive, asn1.Classes.Universal)
        assert isinstance(value, str)
        assert value == u'2.151115727451828646838079.643.2.2.3'

    @pytest.mark.parametrize('filename', ['tc23.ber'])
    def test_case_23(self, decode_ber):
        """
        Unfinished encoding of SID.
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read()
        assert "premature end" in str(e.value)

    @pytest.mark.parametrize('filename', ['tc24.ber'])
    def test_case_24(self, decode_ber):
        """
        Common encoding of OID.
        """
        tag, value = decode_ber.read()
        assert tag == (asn1.Numbers.ObjectIdentifier, asn1.Types.Primitive, asn1.Classes.Universal)
        assert isinstance(value, str)
        assert value == u'2.10000.840.135119.9.2.12301002.12132323.191919.2'


class TestSuiteBoolean:
    @pytest.mark.parametrize('filename', ['tc25.ber'])
    def test_case_25(self, decode_ber):
        """
        Length of value block is more than 1 + encoding of FALSE value.
        Note: The standard says "The contents octets shall consist of a single octet"
        So raises an exception.
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read()
        assert "1 byte" in str(e.value)

    @pytest.mark.parametrize('filename', ['tc26.ber'])
    def test_case_26(self, decode_ber):
        """
        Length of value block is more than 1 + encoding of TRUE value.
        Note: The standard says "The contents octets shall consist of a single octet"
        So raises an exception.
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read()
        assert "1 byte" in str(e.value)

    @pytest.mark.parametrize('filename', ['tc27.ber'])
    def test_case_27(self, decode_ber):
        """
        Absence of value block.
        Note: The size is 3, when the standard says "The contents octets shall consist of a single octet".
        So raises an exception for the length.
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read()
        assert "1 byte" in str(e.value)

    @pytest.mark.parametrize('filename', ['tc28.ber'])
    def test_case_28(self, decode_ber):
        """
        Right encoding for TRUE value.
        """
        tag, value = decode_ber.read()
        assert tag == (asn1.Numbers.Boolean, asn1.Types.Primitive, asn1.Classes.Universal)
        assert isinstance(value, bool)
        assert value

    @pytest.mark.parametrize('filename', ['tc29.ber'])
    def test_case_29(self, decode_ber):
        """
        Right encoding for FALSE value.
        """
        tag, value = decode_ber.read()
        assert tag == (asn1.Numbers.Boolean, asn1.Types.Primitive, asn1.Classes.Universal)
        assert isinstance(value, bool)
        assert not value


class TestSuiteNull:
    @pytest.mark.parametrize('filename', ['tc30.ber'])
    def test_case_30(self, decode_ber):
        """
        Using of value block with length more than 0 octet.
        Note: the standard says "The contents octets shall not contain any octets".
        So raises an exception.
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read()
        assert "0 bytes" in str(e.value)

    @pytest.mark.parametrize('filename', ['tc31.ber'])
    def test_case_31(self, decode_ber):
        """
        Unfinished encoding of value block (+ using of value block with length more than 0 octet).
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read()
        assert "0 bytes" in str(e.value)

    @pytest.mark.parametrize('filename', ['tc32.ber'])
    def test_case_32(self, decode_ber):
        """
        Right NULL encoding.
        """
        tag, value = decode_ber.read()
        assert tag == (asn1.Numbers.Null, asn1.Types.Primitive, asn1.Classes.Universal)
        assert value is None

class TestSuiteBitString:
    @pytest.mark.parametrize('filename', ['tc33.ber'])
    def test_case_33(self, decode_ber):
        """
        Too big value for "unused bits".
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read()
        assert "invalid number of unused bits" in str(e.value)

    @pytest.mark.parametrize('filename', ['tc34.ber'])
    def test_case_34(self, decode_ber):
        """
        Unfinished encoding for value block.
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read()
        assert "premature end" in str(e.value)

    @pytest.mark.parametrize('filename', ['tc35.ber'])
    def test_case_35(self, decode_ber):
        """
        Using of different from BIT STRING types as internal types for constructive encoding.
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read()
        assert "invalid tag" in str(e.value)

    @pytest.mark.parametrize('filename', ['tc36.ber'])
    def test_case_36(self, decode_ber):
        """
        Using of "unused bits" in internal BIT STRINGs with constructive form of encoding.
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read(asn1.ReadFlags.WithUnused)
        assert "unused bits shall be 0" in str(e.value)

    @pytest.mark.parametrize('filename', ['tc37.ber'])
    def test_case_37(self, decode_ber):
        """
        Using of definite form of length block in case of constructive form of encoding.
        """
        tag, (value, unused) = decode_ber.read(asn1.ReadFlags.WithUnused)
        assert tag == (asn1.Numbers.BitString, asn1.Types.Constructed, asn1.Classes.Universal)
        assert isinstance(value, bytes)
        assert value == b'\x00\x10\x10'
        assert unused == 4

    @pytest.mark.parametrize('filename', ['tc38.ber'])
    def test_case_38(self, decode_ber):
        """
        Using of indefinite form of length block in case of constructive form of encoding.
        """
        tag, (value, unused) = decode_ber.read(asn1.ReadFlags.WithUnused)
        assert tag == (asn1.Numbers.BitString, asn1.Types.Constructed, asn1.Classes.Universal)
        assert isinstance(value, bytes)
        assert value == b'\x00\xA3\xB5\xF2\x91\xCD'
        assert unused == 4

    @pytest.mark.parametrize('filename', ['tc39.ber'])
    def test_case_39(self, decode_ber):
        """
        Using of constructive form of encoding for empty BIT STRING.
        """
        tag, (value, unused) = decode_ber.read(asn1.ReadFlags.WithUnused)
        assert tag == (asn1.Numbers.BitString, asn1.Types.Constructed, asn1.Classes.Universal)
        assert isinstance(value, bytes)
        assert value == b''
        assert unused == 0

    @pytest.mark.parametrize('filename', ['tc40.ber'])
    def test_case_40(self, decode_ber):
        """
        Encoding of empty BIT STRING (no value block encoded).
        Note: The standard says "If the bitstring is empty, there shall be no subsequent octets, and the initial octet shall be zero."
        So this case raises an exception
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read(asn1.ReadFlags.WithUnused)
        assert "initial byte is missing" in str(e.value)

class TestSuiteOctetString:
    @pytest.mark.parametrize('filename', ['tc41.ber'])
    def test_case_41(self, decode_ber):
        """
        Using of different from OCTET STRING types as internal types for constructive encoding.
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read()
        assert "invalid tag" in str(e.value)

    @pytest.mark.parametrize('filename', ['tc42.ber'])
    def test_case_42(self, decode_ber):
        """
        Unfinished encoding for value block in case of constructive form of encoding.
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read()
        assert "premature end" in str(e.value)

    @pytest.mark.parametrize('filename', ['tc43.ber'])
    def test_case_43(self, decode_ber):
        """
        Unfinished encoding for value block in case of primitive form of encoding.
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read()
        assert "premature end" in str(e.value)

    @pytest.mark.parametrize('filename', ['tc44.ber'])
    def test_case_44(self, decode_ber):
        """
        Encoding of empty OCTET STRING (no value block encoded).
        """
        tag, value = decode_ber.read()
        assert tag == (asn1.Numbers.OctetString, asn1.Types.Primitive, asn1.Classes.Universal)
        assert isinstance(value, bytes)
        assert value == b''

    @pytest.mark.parametrize('filename', ['tc45.ber'])
    def test_case_45(self, decode_ber):
        """Using of constructive form of encoding for empty OCTET STRING"""
        tag, value = decode_ber.read()
        assert tag == (asn1.Numbers.OctetString, asn1.Types.Constructed, asn1.Classes.Universal)
        assert isinstance(value, bytes)
        assert value == b''

    @pytest.mark.parametrize('filename', ['tc46.ber'])
    def test_case_46(self, decode_ber):
        """
        Using of indefinite length in case of primitive form of encoding.
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read()
        assert " should use the definite form" in str(e.value)

    @pytest.mark.parametrize('filename', ['tc47.ber'])
    def test_case_47(self, decode_ber):
        """
        Using of definite form of length encoding, but use EOC as one of internal string.
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read()
        assert "invalid tag" in str(e.value)

    @pytest.mark.parametrize('filename', ['tc48.ber'])
    def test_case_48(self, decode_ber):
        """
        Using of more than 7 "unused bits" in BIT STRING with constrictive encoding form.
        """
        with pytest.raises(asn1.Error) as e:
            decode_ber.read()
        assert "invalid number of unused bits" in str(e.value)
