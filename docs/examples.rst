Examples
========

Dump
----

This command line utility reads a X509.v3 certificate (in DER or PEM encoding),
decodes it and outputs a textual representation. It more or less mimics
`openssl asn1parse <https://docs.openssl.org/1.1.1/man1/openssl-asn1parse/>`_:

.. code-block:: shell

  $ python examples/dump.py examples/test.crt

  [U] SEQUENCE
    [U] SEQUENCE
      [C] 0x0
        [U] INTEGER: 2
      [U] INTEGER: 5424
      [U] SEQUENCE
        [U] OBJECT: 1.2.840.113549.1.1.5
        [U] NULL: None
      [U] SEQUENCE
        [U] SET
          [U] SEQUENCE
            [U] OBJECT: 2.5.4.6
            [U] PRINTABLESTRING: --
        [U] SET
          [U] SEQUENCE
            [U] OBJECT: 2.5.4.8
            [U] PRINTABLESTRING: SomeState
        [U] SET
          [U] SEQUENCE
            [U] OBJECT: 2.5.4.7
            [U] PRINTABLESTRING: SomeCity
        [U] SET
          [U] SEQUENCE
            [U] OBJECT: 2.5.4.10
            [U] PRINTABLESTRING: SomeOrganization
        [U] SET
          [U] SEQUENCE
            [U] OBJECT: 2.5.4.11
            [U] PRINTABLESTRING: SomeOrganizationalUnit
        [U] SET
          [U] SEQUENCE
            [U] OBJECT: 2.5.4.3
            [U] PRINTABLESTRING: localhost.localdomain
        [U] SET
          [U] SEQUENCE
            [U] OBJECT: 1.2.840.113549.1.9.1
            [U] IA5STRING: root@localhost.localdomain
      [U] SEQUENCE
        [U] UTCTIME: 080205092331Z
        [U] UTCTIME: 090204092331Z
      [U] SEQUENCE
        [U] SET
          [U] SEQUENCE
            [U] OBJECT: 2.5.4.6
            [U] PRINTABLESTRING: --
        [U] SET
          [U] SEQUENCE
            [U] OBJECT: 2.5.4.8
            [U] PRINTABLESTRING: SomeState
        [U] SET
          [U] SEQUENCE
            [U] OBJECT: 2.5.4.7
            [U] PRINTABLESTRING: SomeCity
        [U] SET
          [U] SEQUENCE
            [U] OBJECT: 2.5.4.10
            [U] PRINTABLESTRING: SomeOrganization
        [U] SET
          [U] SEQUENCE
            [U] OBJECT: 2.5.4.11
            [U] PRINTABLESTRING: SomeOrganizationalUnit
        [U] SET
          [U] SEQUENCE
            [U] OBJECT: 2.5.4.3
            [U] PRINTABLESTRING: localhost.localdomain
        [U] SET
          [U] SEQUENCE
            [U] OBJECT: 1.2.840.113549.1.9.1
            [U] IA5STRING: root@localhost.localdomain
      [U] SEQUENCE
        [U] SEQUENCE
          [U] OBJECT: 1.2.840.113549.1.1.1
          [U] NULL: None
        [U] BIT STRING: 0xb'0030818902818100D51...10610203010001'
      [C] BIT STRING
        [U] SEQUENCE
          [U] SEQUENCE
            [U] OBJECT: 2.5.29.14
            [U] OCTET STRING: 0xb'04140A4BFA8754177E30B4217156510FD291C3300236'
          [U] SEQUENCE
            [U] OBJECT: 2.5.29.35
            [U] OCTET STRING: 0xb'3081DE80140A4...D61696E82021530'
          [U] SEQUENCE
            [U] OBJECT: 2.5.29.19
            [U] OCTET STRING: 0xb'30030101FF'
    [U] SEQUENCE
      [U] OBJECT: 1.2.840.113549.1.1.5
      [U] NULL: None
    [U] BIT STRING: 0xb'004E124658A357C59AABFA3...8A6245C7FC58B45A'

The main function is ``pretty_print``:

.. code-block:: python
   :linenos:

   def pretty_print(input_stream, output_stream, indent=0):
        """Pretty print ASN.1 data."""
        while not input_stream.eof():
            tag = input_stream.peek()
            if tag.typ == asn1.Types.Primitive:
                tag, value = input_stream.read()
                output_stream.write(' ' * indent)
                output_stream.write('[{}] {}: {}\n'.format(class_id_to_string(tag.cls),
                    tag_id_to_string(tag.nr), value_to_string(tag.nr, value)))
            elif tag.typ == asn1.Types.Constructed:
                output_stream.write(' ' * indent)
                output_stream.write('[{}] {}\n'.format(class_id_to_string(tag.cls),
                    tag_id_to_string(tag.nr)))
                input_stream.enter()
                pretty_print(input_stream, output_stream, indent + 2)
                input_stream.leave()

This code:

* **line 3**: Loops until its reaches the end of the input stream (with `Decoder.eof()`).

* **line 4**: Looks (with `Decoder.peek()`) at the current tag.

* **line 5**: If the tag is primitive (``TypePrimitive``) ...

* **line 6**: ... the code reads (with `Decoder.read()`) the current tag.

* **line 8**: Then it displays its number and value (after some mapping to be more user-fiendly).

* **line 10**: If the tag is constructed (``TypeConstructed``) ...

* **line 12**: ... the code displays its class and number.

* **line 14**: Then it enters inside the tag and ...

* **line 15**: ... calls itself recursively to decode the ASN.1 tags inside.

* **line 16**: Leaves the current constructed tag (with `Decoder.leave()`) to continue the decoding of its siblings.
