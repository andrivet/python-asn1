.. start-badges

|build| |version| |wheel| |supported-versions| |supported-implementations|

.. |build| image:: https://github.com/andrivet/python-asn1/actions/workflows/tests.yml/badge.svg
    :target: https://github.com/andrivet/python-asn1
    :alt: GitHub Actions

.. |docs| image:: https://app.readthedocs.org/projects/python-asn1/badge/?style=flat
    :target: https://python-asn1.readthedocs.io/en/latest/
    :alt: Documentation Status

.. |version| image:: https://img.shields.io/pypi/v/asn1.svg?style=flat
    :alt: PyPI Package latest release
    :target: https://pypi.org/project/asn1/

.. |wheel| image:: https://img.shields.io/pypi/wheel/asn1.svg?style=flat
    :alt: PyPI Wheel
    :target: https://pypi.org/project/asn1/

.. |supported-versions| image:: https://img.shields.io/pypi/pyversions/asn1.svg?style=flat
    :alt: Supported versions
    :target: https://pypi.org/project/asn1/

.. |supported-implementations| image:: https://img.shields.io/pypi/implementation/asn1.svg?style=flat
    :alt: Supported implementations
    :target: https://pypi.org/project/asn1/


.. end-badges

========
Overview
========

Python-ASN1 is a simple ASN.1 encoder and decoder for Python 2.7 and 3.5+.

Features
========

- Support BER (parser) and DER (parser and generator) encoding (including indefinite lengths)
- 100% python, compatible with version 2.7, 3.5 and higher
- Can be integrated by just including a file into your project
- Support most common ASN.1 types including REAL (encoding and decoding).

Dependencies
==============

Python-ASN1 relies on `Python-Future <https://python-future.org>`_ for Python 2 and 3 compatibility. To install Python-Future:

.. code-block:: sh

  pip install future

Python-ASN1 relies on `type hints <https://docs.python.org/3/library/typing.html>`_. For Python 2.7, a backport of the standard library typing module has to be installed:

.. code-block:: sh

  pip install typing

This is not necessary for Python 3.5 and higher since it is part of the standard library.

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

Contributing
============

Contributions to Python-ASN1 are welcome. If you want to contribute, please fork the repository on GitHub, make your changes and submit a pull request (PR).
Please make sure that your code is properly tested and that all tests pass.
In particular, tests should pass for old versions of Python (2.7 and from 3.5 to 3.14).
You can use the provided Docker file to test your code on all those versions of Python.

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
* Filippo Santovito (filippo.santovito@gmail.com)
