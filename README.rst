cd C:\Users\asus\python-asn1-1\examples

python dump.py --pem private_key.pem

python rsa_key_completion.py

python finalize_rsa_key.py


teststststtststtsttsst


========
Overview
========

Python-ASN1 is a simple ASN.1 encoder and decoder for Python 2.7 and 3.5+.

Features
========

- Support BER (parser) and DER (parser and generator) encoding (except indefinite lengths)
- 100% python, compatible with version 2.7, 3.5 and higher
- Can be integrated by just including a file into your project


Dependencies
==============

Python-ASN1 relies on `Python-Future <https://python-future.org>`_ for Python 2 and 3 compatibility. To install Python-Future:

.. code-block:: sh

  pip install future


How to install Python-asn1
==========================

Install from PyPi with the following:

.. code-block:: sh

  pip install asn1

or download the repository from `GitHub <https://github.com/andrivet/python-asn1>`_ and install with the following:

.. code-block:: sh

  python setup.py install

You can also simply include ``asn1.py`` into your project.


How to use Python-asn1
======================

.. note:: You can find more detailed documentation on the `Usage`_ page.

.. _Usage: usage.rst

Encoding
--------

If you want to encode data and retrieve its DER-encoded representation, use code such as:

.. code-block:: python

  import asn1

  encoder = asn1.Encoder()
  encoder.start()
  encoder.write('1.2.3', asn1.Numbers.ObjectIdentifier)
  encoded_bytes = encoder.output()


Decoding
--------

If you want to decode ASN.1 from DER or BER encoded bytes, use code such as:

.. code-block:: python

  import asn1

  decoder = asn1.Decoder()
  decoder.start(encoded_bytes)
  tag, value = decoder.read()


Documentation
=============

The complete documentation is available on Read The Docs:

`python-asn1.readthedocs.io <https://python-asn1.readthedocs.io/en/latest/>`_


License
=======

Python-ASN1 is free software that is made available under the MIT license.
Consult the file LICENSE that is distributed together with this library for
the exact licensing terms.

Copyright
=========

The following people have contributed to Python-ASN1. Collectively they own the copyright of this software.

* Geert Jansen (geert@boskant.nl): `original implementation <https://github.com/geertj/python-asn1>`_.
* Sebastien Andrivet (sebastien@andrivet.com)
