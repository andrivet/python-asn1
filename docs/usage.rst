Usage
=====

.. note::

   You can find a complete example in `examples`.


The Python-ASN1 API is exposed by a single Python module named
`asn1`. The main interface is provided by the following classes:

* `Encoder`: Used to encode ASN.1.
* `Decoder`: Used to decode ASN.1.
* `Error`: Exception used to signal errors.

Type Mapping
------------

The Python-ASN1 encoder and decoder make a difference between primitive and
constructed data types. Primitive data types can be encoded and decoded
directly with `read()` and `write()` methods.  For these types, ASN.1 types are
mapped directly to Python types and vice versa, as per the table below:

================ ========== =========== =============
ASN.1 type       Tag Number Decoding    Encoding
================ ========== =========== =============
Boolean          0x01       bool        bool
Integer          0x02       int         int
Null             0x05       None        None
ObjectIdentifier 0x06       str
Real             0x09       float       float
Enumerated       0x0A       int
================ ========== =========== =============

Because ASN.1 has more data types than Python, the situation arises that one Python
type corresponds to multiple ASN.1 types. In this situation, the to be encoded
ASN.1 type cannot be determined from the Python type. The solution
implemented in Python-ASN1 is that the most frequently used type will be the
implicit default. This is indicated in the ``Encoding`` column.
If another type is desired than that must be specified
explicitly through the API.

Some ASN.1 types can be either primitive or constructed. They can be encoded
and decoded like primitive types. The following table shows the mapping between
ASN.1 types and Python types.

================ ========== =========== =============
ASN.1 type       Tag Number Decoding    Encoding
================ ========== =========== =============
BitString        0x03       bytes
OctetString      0x04       bytes       bytes
UTF8String       0x0C       str
NumericString    0x12       str
PrintableString  0x13       str         str
T61String        0x14       str
VideotextString  0x15       str
IA5String        0x16       str
GraphicString    0x19       str
VisibleString    0x1A       str
GeneralString    0x1B       str
UniversalString  0x1C       str
CharacterString  0x1D       str
UnicodeString    0x1E       str
================ ========== =========== =============

For constructed types, there are two possibilities. The first is to treat them
as a sequence of types. In this case, the encoder and decoder will automatically
map the ASN.1 types to Python types and vice versa.

================ ========== =========== =============
ASN.1 type       Tag Number Decoding    Encoding
================ ========== =========== =============
Sequence         0x10       list        list
Set              0x11       list
================ ========== =========== =============

The second possibility is to treat them as a stack of types. In this approach,
the user needs to explicitly enter/leave the constructed type using the
`Encoder.enter()` and `Encoder.leave()` methods of the encoder and the
`Decoder.enter()` and `Decoder.leave()` methods of the decoder.

Encoding
--------

If you want to encode data and retrieve its DER-encoded representation, use code such as:

.. code-block:: python

  import asn1

  encoder = asn1.Encoder()
  encoder.start()
  encoder.write('1.2.3', asn1.Numbers.ObjectIdentifier)
  encoded_bytes = encoder.output()

It is also possible to encode data directly to a file or any stream:

.. code-block:: python

  import asn1

  with open('output.der', 'wb') as f:
    encoder = asn1.Encoder()
    encoder.start(f)
    encoder.write('1.2.3', asn1.Numbers.ObjectIdentifier)

You can encode complex data structures such as sequences and sets:

.. code-block:: python

  import asn1

  with open('output.der', 'wb') as f:
        encoder = asn1.Encoder()
        encoder.start(f)
        encoder.write(['test1', 'test2', [
            1,
            0.125,
            b'\x01\x02\x03'
        ]])

ASN.1 types are automatically mapped to Python types.
If you want to precisely specify the ASN.1 type, you have to use the `Encoder.enter()` and `Encoder.leave()` methods:

.. code-block:: python

  import asn1

  with open('output.der', 'wb') as f:
        encoder = asn1.Encoder()
        encoder.start(f)
        encoder.enter(asn1.Numbers.Sequence)
        encoder.write('test1', asn1.Numbers.PrintableString)
        encoder.write('test2', asn1.Numbers.PrintableString)
        encoder.enter(asn1.Numbers.Sequence)
        encoder.write(1, asn1.Numbers.Integer)
        encoder.write(0.125, asn1.Numbers.Real)
        encoder.write(b'\x01\x02\x03', asn1.Numbers.OctetString)
        encoder.leave()
        encoder.leave()

This also allows to encode data progressively, without having to keep everything in memory.

Decoding
--------

If you want to decode ASN.1 from DER or BER encoded bytes, use code such as:

.. code-block:: python

  import asn1

  decoder = asn1.Decoder()
  decoder.start(encoded_bytes)
  tag, value = decoder.read()

It is also possible to decode data directly from a file or any stream:

.. code-block:: python

  import asn1

  with open('input.der', 'rb') as f:
    decoder = asn1.Decoder()
    decoder.start(f)
    tag, value = decoder.read()

You can decode complex data structures. The decoder will automatically map ASN.1 types to Python types:

.. code-block:: python

    import asn1

    with open('example7.der', 'rb') as f:
        decoder = asn1.Decoder()
        decoder.start(f)
        tag, value = decoder.read()
        print(tag)
        pprint.pprint(value)

You can ask the decoder to return the number of unused bits when decoding a BitString:

.. code-block:: python

    import asn1

    encoded = b'\x23\x0C\x03\x02\x00\x0B\x03\x02\x00\x0B\x03\x02\x04\x0F'
    decoder = asn1.Decoder()
    decoder.start(encoded)
    tag, (value, unused) = decoder.read(asn1.ReadFlags.WithUnused)
    print('Tag: ', tag)
    print('Value: ', value)
    print('Unused bits: ', unused)

The flag ``ReadFlags.WithUnused`` can be used with any ASN.1 type. When used, the read method will return a tuple with the value and the number of unused bits.
If the type is not a BitString, the number of unused bits is always 0.


Definite and indefinite-length encoding
---------------------------------------

By default, `Encoder` encodes constructed types in definite-length encoding:

.. code-block:: python

  import asn1

  encoder = asn1.Encoder()
  encoder.start()
  encoder.write([b'foo'])
  assert encoder.output() == b'\x30\x05\x04\x03foo'

To use indefinite-length encoding instead, construct the `Encoder` with `definite=False`:

.. code-block:: python

  import asn1

  encoder = asn1.Encoder(definite=False)
  encoder.start()
  encoder.write([b'foo'])
  assert encoder.output() == b'\x30\x80\x04\x03foo\x00\x00'

This setting will apply to all output generated by this `Encoder` instance, including any `.enter()`, `.leave()` and `.construct()` calls.


Constants
---------

A few constants are defined in the `asn1` module. The
constants immediately below correspond to ASN.1 tag numbers.
They can be used as
the ``nr`` parameter of the
`Encoder.write()` method, and are returned as the
first part of a ``(nr, typ, cls)`` tuple as returned by
`Decoder.peek()` and
`Decoder.read()`.

==================================== ===========
Constant                             Value (hex)
==================================== ===========
Numbers.Boolean                      0x01
Numbers.Integer                      0x02
Numbers.BitString                    0x03
Numbers.OctetString                  0x04
Numbers.Null                         0x05
Numbers.ObjectIdentifier             0x06
Numbers.ObjectDescriptor             0x07
Numbers.External                     0x08
Numbers.Real                         0x09
Numbers.Enumerated                   0x0a
Numbers.EmbeddedPDV                  0x0b
Numbers.UTF8String                   0x0c
Numbers.RelativeOID                  0x0d
Numbers.Time                         0x0e
Numbers.Sequence                     0x10
Numbers.Set                          0x11
Numbers.NumericString                0x12
Numbers.PrintableString              0x13
Numbers.T61String                    0x14
Numbers.VideotextString              0x15
Numbers.IA5String                    0x16
Numbers.UTCTime                      0x17
Numbers.GeneralizedTime              0x18
Numbers.GraphicString                0x19
Numbers.VisibleString                0x1a
Numbers.GeneralString                0x1b
Numbers.UniversalString              0x1c
Numbers.CharacterString              0x1d
Numbers.UnicodeString                0x1e
Numbers.Date                         0x1f
Numbers.TimeOfDay                    0x20
Numbers.DateTime                     0x21
Numbers.Duration                     0x22
Numbers.OIDinternationalized         0x23
Numbers.RelativeOIDinternationalized 0x24
==================================== ===========

The following constants define the two available encoding types (primitive
and constructed) for ASN.1 data types. As above they can be used with the
`Encoder.write()` and are returned by
`Decoder.peek()` and
`Decoder.read()`.

=================== ===========
Constant            Value (hex)
=================== ===========
Types.Constructed   0x20
Types.Primitive     0x00
=================== ===========

Finally the constants below define the different ASN.1 classes. As above
they can be used with the `Encoder.write()` and are
returned by `Decoder.peek()` and
`Decoder.read()`.

=================== ===========
Constant            Value (hex)
=================== ===========
Classes.Universal   0x00
Classes.Application 0x40
Classes.Context     0x80
Classes.Private     0xc0
=================== ===========
