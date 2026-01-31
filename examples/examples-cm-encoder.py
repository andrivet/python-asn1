# -*- coding: utf-8 -*-
#
# This file is part of Python-ASN1. Python-ASN1 is free software that is
# made available under the MIT license. Consult the file "LICENSE" that
# is distributed together with this file for the exact licensing terms.
#
# Python-ASN1 is copyright (c) 2007-2016 by the Python-ASN1 authors. See
# the file "AUTHORS" for a complete overview.

from __future__ import absolute_import, division, print_function, unicode_literals

from builtins import open, str
import asn1
import binascii
import pprint


def example1():
    """Encoding an object identifier."""
    print("Example 1")
    with asn1.Encoder() as encoder:
        encoder.write("1.2.3", asn1.Numbers.ObjectIdentifier)
        print(str(binascii.hexlify(encoder.output(), " ", 1).upper(), encoding="ascii"))
    print()


def example2():
    """Encoding an object identifier directly to a file."""
    print("Example 2")
    with open("example2.der", "wb") as f:
        with asn1.Encoder(
            stream=f, encoding=asn1.Encoding.DER
        ) as encoder:  # CER is the default when using a stream
            encoder.write("1.2.3", asn1.Numbers.ObjectIdentifier)


def example3():
    """Encoding of complex data."""
    print("Example 3")
    with open("example3.der", "wb") as f:
        with asn1.Encoder(
            stream=f, encoding=asn1.Encoding.DER
        ) as encoder:  # CER is the default when using a stream
            encoder.write(["test1", "test2", [1, 0.125, b"\x01\x02\x03"]])
    print()


def example4():
    """Encoding of sequences."""
    print("Example 4")
    with asn1.Encoder() as encoder:
        with encoder.sequence():
            encoder.write("test1", asn1.Numbers.PrintableString)
            encoder.write("test2", asn1.Numbers.PrintableString)
            with encoder.sequence():
                encoder.write(1, asn1.Numbers.Integer)
                encoder.write(0.125, asn1.Numbers.Real)
                encoder.write(b"\x01\x02\x03", asn1.Numbers.OctetString)
        print(str(binascii.hexlify(encoder.output(), " ", 1).upper(), encoding="ascii"))
    print()


def example5():
    """Using CER encoding with a stream (file)."""
    print("Example 5")
    with open("example6.cer", "wb") as f:
        with asn1.Encoder(stream=f) as encoder:
            encoder.write("1.2.3", asn1.Numbers.ObjectIdentifier)


def example6():
    """Using DER encoding with a stream (file)."""
    print("Example 6")
    with open("example7.der", "wb") as f:
        with asn1.Encoder(stream=f, encoding=asn1.Encoding.DER) as encoder:
            encoder.write("1.2.3", asn1.Numbers.ObjectIdentifier)


example1()
example2()
example3()
example4()
example5()
example6()
