========
Overview
========

DERlite is a encoder and parser for DER-encoded (and some BER-encoded) ASN.1 data.

DERlite requires Python 3.5 (particularly for some features of the
``bytes`` and ``int`` classes).
It has no hard dependencies beyond the standard library,
but requires T.61 and ISO-2022 codecs to be available in order
to decode all valid string types.

Features
========

- Straightforward encoding of most primitive types (except character
  strings), SETs, SEQUENCEs, and explicit tags.
- Correct decoding of character string types.
- Complex application-specific types can be supported in an object-oriented way.
- Fairly easy to hand-write a parser and an encoder for your chosen
  ASN.1 structures.
- Easy to mix ad-hoc and more structured styles.
- 100% python, compatible with version 3.5 and higher

  
Missing Features
================

Datetimes always use GeneralizedTime rather than UTCTime. This is
usually preferable, except that some specifications such as PKIX
require the use of UTCTime for dates during the late 20th century.

There's no support for many BER features, in particular,
indefinite-length encodings and constructed primitives.

The entire encoded object must fit in a ``bytes`` object;
there is no support for streaming either during encoding or decoding.

Usage Example
=============

Decoding a PKIX RSAPublicKey structure::

  from derlite import Decoder, Tag
  
  decoder = Decoder(some_bytes)
  decoder.enter(Tag.Sequence)
  modulus = decoder.read_integer()
  exponent = decoder.read_integer()
  decoder.leave()

Creating an LDAP AddRequest message to add two attributes to a given
DN, assuming that ``dn``, ``attr1``, and ``attr2`` are objects
implementing the ``.encode_der()`` or ``.as_der()`` informal protocol
methods::

  from derlite import Encoder, Tag

  addRequestTag = Tag(16, cls=Tag.Application)
  
  encoder = Encoder()
  encoder.enter(abandonRequestTag)
  encoder.enter(Tag.Sequence)
  encoder.write(dn)
  encoder.write( [ attr1, attr2 ] )
  encoder.leave()
  encoder.leave()

  some_bytes = encoder.getvalue()

In addition to the ``Encoder`` and ``Decoder`` classes, DERlite
provides a ``Tag`` class for storing tag numbers along with their
tag-class and constructed flag; ``Oid`` for manipulating OIDs;
and ``OptionBitSet`` for handling sets of flags stored in BIT
STRINGs (as is common in some ASN.1 specifications).

Other Resources
===============

Other modules providing DER/BER functionality:

- `pyasn1`_ is a full-featured ASN.1 implementation, including the ability
  to parse ASN.1 specifications and generate codec classes.
- `asn1`_ is similar to (and the inspiration for) DERlite. It is less
  featureful, but a more mature project.
- `python-asn1crypto`_ is focused specifically on PKIX/X.500 structures.


To get a quick understanding of BER and DER, see `A Layman's Guide to a Subset of ASN.1, BER, and DER <http://luca.ntop.org/Teaching/Appunti/asn1.html>`_.
For a more comprehensive description of the standard, try `the books on this page <http://www.oss.com/asn1/resources/books-whitepapers-pubs/asn1-books.html#dubuisson>`_, in particular Olivier Dubuisson's, which can be read for free.

For a look into some of the horrors of real-world ASN.1 implementations, see Peter Gutmann's `X.509 Style Guide <https://www.cs.auckland.ac.nz/~pgut001/pubs/x509guide.txt>`_.

And finally, some (but not all) of the underlying standards can be downloaded from ITU or ECMA.


History
=======

DERlite began as a set of conveniences and extensions to the
`asn1 module`_ by Geert Jansen and Sebastien Andrivet.  The current
interface is incompatible in many ways (hence the new name), and
little or none of the original code remains, but usage should be
similar.

The name DERlite was chosen because this module is lighter-weight than
a full ASN.1 implementation such as `pyasn1`_, and is hopefully
pleasant to use (though it would be an exaggeration to say that
working with ASN.1 is a "delight").

Author
======

DERlite was written by Wim Lewis (`wiml@hhhh.org`_). It may be used
under the terms of the `MIT License`_.

Bug reports, suggestions, and patches are gratefully accepted via
Github or via email.

.. _asn1: https://github.com/andrivet/python-asn1
.. _pyasn1: https://github.com/etingof/pyasn1
.. _PyPI: https://pypi.python.org/pypi
.. _asn1 module: https://github.com/andrivet/python-asn1
.. _python-asn1crypto: https://github.com/wbond/asn1crypto
.. _MIT License: https://opensource.org/licenses/MIT
.. _wiml@hhhh.org: mailto:wiml@hhhh.org


