# -*- coding: utf-8 -*-
#
# This file is part of Python-ASN1. Python-ASN1 is free software that is
# made available under the MIT license. Consult the file "LICENSE" that
# is distributed together with this file for the exact licensing terms.
#
# Python-ASN1 is copyright (c) 2007-2016 by the Python-ASN1 authors. See
# the file "AUTHORS" for a complete overview.

from __future__ import absolute_import, division, print_function, unicode_literals

from builtins import open, bytes, str
import asn1
import base64
import binascii
import io
import sys
import typing
import optparse


class PEMBinaryIO(io.RawIOBase):
    """A RawIOBase implementation that reads and writes PEM encoded data."""
    def __init__(self, stream):
        self._stream = stream
        self._buffer = b''
        self._state = 0

    def read(self, size=-1):
        while size < 0 or len(self._buffer) < size:
            line = self._stream.readline()
            if not line:
                break
            line = line.strip()

            if self._state == 0:
                if line.startswith('-----BEGIN'):
                    self._state = 1
            elif self._state == 1:
                if line.startswith('-----END'):
                    self._state = 2
                else:
                    self._buffer += base64.b64decode(line)

        # All data?
        if size < 0:
            data, self._buffer = self._buffer, b''
            return data

        # Only a portion of the data
        data, self._buffer = self._buffer[:size], self._buffer[size:]
        return data

    def write(self, data):
        self._stream.write(base64.b64encode(data).decode('ascii'))
        self._stream.write('\n')

    def close(self):
        self._stream.close()


tag_id_to_string_map = {
    asn1.Numbers.Boolean: "BOOLEAN",
    asn1.Numbers.Integer: "INTEGER",
    asn1.Numbers.BitString: "BIT STRING",
    asn1.Numbers.Null: "NULL",
    asn1.Numbers.OctetString: "OCTET STRING",
    asn1.Numbers.ObjectIdentifier: "OBJECT IDENTIFIER",
    asn1.Numbers.ObjectDescriptor: "OBJECT DESCRIPTOR",
    asn1.Numbers.PrintableString: "PRINTABLESTRING",
    asn1.Numbers.IA5String: "IA5STRING",
    asn1.Numbers.UTCTime: "UTCTIME",
    asn1.Numbers.GeneralizedTime: "GENERALIZED TIME",
    asn1.Numbers.Enumerated: "ENUMERATED",
    asn1.Numbers.Sequence: "SEQUENCE",
    asn1.Numbers.Set: "SET"
}

class_id_to_string_map = {
    asn1.Classes.Universal: "U",
    asn1.Classes.Application: "A",
    asn1.Classes.Context: "C",
    asn1.Classes.Private: "P"
}

object_id_to_string_map = {
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",

    "1.3.6.1.5.5.7.1.1": "authorityInfoAccess",

    "2.5.4.3": "commonName",
    "2.5.4.4": "surname",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "countryName",
    "2.5.4.7": "localityName",
    "2.5.4.8": "stateOrProvinceName",
    "2.5.4.9": "streetAddress",
    "2.5.4.10": "organizationName",
    "2.5.4.11": "organizationalUnitName",
    "2.5.4.12": "title",
    "2.5.4.13": "description",
    "2.5.4.42": "givenName",

    "1.2.840.113549.1.9.1": "emailAddress",

    "2.5.29.14": "X509v3 Subject Key Identifier",
    "2.5.29.15": "X509v3 Key Usage",
    "2.5.29.16": "X509v3 Private Key Usage Period",
    "2.5.29.17": "X509v3 Subject Alternative Name",
    "2.5.29.18": "X509v3 Issuer Alternative Name",
    "2.5.29.19": "X509v3 Basic Constraints",
    "2.5.29.30": "X509v3 Name Constraints",
    "2.5.29.31": "X509v3 CRL Distribution Points",
    "2.5.29.32": "X509v3 Certificate Policies Extension",
    "2.5.29.33": "X509v3 Policy Mappings",
    "2.5.29.35": "X509v3 Authority Key Identifier",
    "2.5.29.36": "X509v3 Policy Constraints",
    "2.5.29.37": "X509v3 Extended Key Usage"
}


def tag_id_to_string(identifier):
    """Return a string representation of a ASN.1 id."""
    if identifier in tag_id_to_string_map:
        return tag_id_to_string_map[identifier]
    return '{:#02x}'.format(identifier)


def class_id_to_string(identifier):
    """Return a string representation of an ASN.1 class."""
    if identifier in class_id_to_string_map:
        return class_id_to_string_map[identifier]
    raise ValueError('Illegal class: {:#02x}'.format(identifier))


def object_identifier_to_string(identifier):
    if identifier in object_id_to_string_map:
        return object_id_to_string_map[identifier]
    return identifier

def value_to_string(tag_number, value):
    if tag_number == asn1.Numbers.ObjectIdentifier:
        return object_identifier_to_string(value)
    elif isinstance(value, bytes):
        return str(binascii.hexlify(value, ' ', 1).upper(), encoding='ascii')
    elif isinstance(value, str):
        return value
    else:
        return repr(value)


def pretty_print(input_stream, output_stream, indent=0):
    """Pretty print ASN.1 data."""
    while not input_stream.eof():
        tag = input_stream.peek()
        if tag is None:
            return
        if tag.typ == asn1.Types.Primitive:
            tag, value = input_stream.read()
            output_stream.write(' ' * indent)
            output_stream.write('[{}] {}: {}\n'.format(class_id_to_string(tag.cls), tag_id_to_string(tag.nr), value_to_string(tag.nr, value)))
        elif tag.typ == asn1.Types.Constructed:
            output_stream.write(' ' * indent)
            output_stream.write('[{}] {}\n'.format(class_id_to_string(tag.cls), tag_id_to_string(tag.nr)))
            input_stream.enter()
            pretty_print(input_stream, output_stream, indent + 2)
            input_stream.leave()


# Main script

parser = optparse.OptionParser()
parser.add_option('-p', '--pem', dest='mode', action='store_const', const='pem', help='PEM encoded input')
parser.add_option('-o', '--output', dest='output', help='output to FILE instead', metavar='FILE')
parser.set_default('mode', 'pem')
(opts, args) = parser.parse_args()

if len(args) != 1:
    parser.error('Please provide an input file')
    exit(1)

decoder = asn1.Decoder()

if opts.mode == 'pem':
    decoder.start(PEMBinaryIO(open(args[0], 'r')))
else:
    decoder.start(typing.cast(io.RawIOBase, open(args[0], 'rb')))

if opts.output:
    output_file = open(opts.output, 'w')
else:
    output_file = typing.cast(io.TextIOWrapper, sys.stdout)

pretty_print(decoder, output_file)
