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

================ ================= =============
ASN.1 type       Python type       Default
================ ================= =============
Boolean          bool              yes
Integer          int               yes
OctetString      bytes             yes
PrintableString  str               yes
Null             None              yes
ObjectIdentifier bytes             no
Enumerated       int               no
================ ================= =============

The column **default** is relevant for encoding only.  Because
ASN.1 has more data types than Python, the situation arises that one Python
type corresponds to multiple ASN.1 types. In this situation the encoded
ASN.1 type cannot be determined from the Python type. The solution
implemented in Python-ASN1 is that the most frequently used type will be the
implicit default, and if another type is desired than that must be specified
explicitly through the API.

For constructed types, no type mapping is done at all, even for types where
such a mapping would be possible such as the ASN.1 type **sequence
of** which could be mapped to a Python list. For such types a stack
based approach is used instead. In this approach, the user needs to
explicitly enter/leave the constructed type using the
`Encoder.enter()` and `Encoder.leave()` methods of the encoder and the
`Decoder.enter()` and `Decoder.leave()` methods of the decoder.


Encoding
--------

If you want to encode data and retrieve its DER-encoded representation, use code such as:

.. code-block:: python

  import asn1

  encoder = asn1.Encoder()
  encoder.start()
  encoder.write('1.2.3', asn1.ObjectIdentifier)
  encoded_bytes = encoder.output()


Decoding
--------

If you want to decode ASN.1 from DER or BER encoded bytes, use code such as:

.. code-block:: python

  import asn1

  decoder = asn1.Decoder()
  decoder.start(encoded_bytes)
  tag, value = decoder.read()


Constants
---------

A few constants are defined in the `asn1` module. The
constants immediately below correspond to ASN.1 numbers. They can be used as
the ``nr`` parameter of the
`Encoder.write()` method, and are returned as the
first part of a ``(nr, typ, cls)`` tuple as returned by
`Decoder.peek()` and
`Decoder.read()`.

================ ===========
Constant         Value (hex)
================ ===========
Boolean          0x01
Integer          0x02
OctetString      0x04
Null             0x05
ObjectIdentifier 0x06
Enumerated       0x0a
Sequence         0x10
Set              0x11
================ ===========

The following constants define the two available encoding types (primitive
and constructed) for ASN.1 data types. As above they can be used with the
`Encoder.write()` and are returned by
`Decoder.peek()` and
`Decoder.read()`.

================ ===========
Constant         Value (hex)
================ ===========
TypeConstructed  0x20
TypePrimitive    0x00
================ ===========

Finally the constants below define the different ASN.1 classes.  As above
they can be used with the `Encoder.write()` and are
returned by `Decoder.peek()` and
`Decoder.read()`.

================ ===========
Constant         Value (hex)
================ ===========
ClassUniversal   0x00
ClassApplication 0x40
ClassContext     0x80
ClassPrivate     0xc0
================ ===========
