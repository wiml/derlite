#
# This file is part of DERlite.
#
# Copyright 2017 by Wim Lewis.
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

"""
Utilities for constructing and parsing DER-encoded data.

"""

__version__ = "0.2.1"
__docformat__ = 'reStructuredText'

import datetime, io, re

class Tag (tuple):
    """A named tuple to represent ASN.1 tags and to hold tag constants."""

    # Tag values in the UNIVERSAL class.
    _universal_tags = (
        # The primitive types
        ( 'Boolean', 0x01 ),
        ( 'Integer', 0x02 ),
        ( 'BitString', 0x03 ),
        ( 'OctetString', 0x04 ),
        ( 'Null', 0x05 ),
        ( 'ObjectIdentifier', 0x06 ),
        ( 'Enumerated', 0x0a ),
        ( 'UTCTime', 0x17 ),
        ( 'GeneralizedTime', 0x18 ),

        # The constructed types
        ( 'Sequence', 0x10 ),
        ( 'Set', 0x11 ),

        # The mess of character-string types
        ( 'IA5String', 0x16 ),        # ASCII, approximately
        ( 'UTF8String', 0x0c ),       # UTF-8
        ( 'UniversalString', 0x1c ),  # UCS-32
        ( 'BMPString', 0x1e ),        # UCS-16
        ( 'NumericString', 0x12 ),    # ASCII subset
        ( 'PrintableString', 0x13 ),  # ASCII subset
        ( 'VisibleString', 0x1a ),    # ASCII subset

        # The following are all based on ISO-2022, which uses escape
        # sequences to switch into various other character sets.
        # The TeletexString and VideotexString encodings allow the
        # use of ISO-2022 escape sequences, but are defined to start out
        # with a particular set of character sets already invoked.
        ( 'TeletexString', 0x14 ),    # CCITT T.61, or ISO-IR 102+103
        ( 'VideotexString', 0x15 ),   # CCITT T.101
        ( 'GraphicString', 0x19 ),
        ( 'GeneralString', 0x1b ),
    )

    Universal = 0x00
    Application = 0x40
    Context = 0x80
    Private = 0xC0

    __slots__ = ()
    _fields = ('tag', 'constructed', 'cls')

    tag = property(lambda x: x[0])
    constructed = property(lambda x: x[1])
    cls = property(lambda x: x[2])

    def __new__(self, tag, constructed = False, cls = 0x00):
        # type: (int, bool, int) -> Tag
        return tuple.__new__(self, (tag, constructed, cls))
    
    def __repr__(self):
        if self.cls == Tag.Universal and ( self.constructed == (self.tag in (0x11, 0x10))):
            for (n, v) in self._universal_tags:
                if v == self.tag:
                    return 'Tag.' + n
        clsnames = { 0x00: 'Universal',
                     0x40: 'Application',
                     0x80: 'Context',
                     0xC0: 'Private' }
        cls = clsnames.get(self.cls)
        if cls is None:
            cls = repr(self.cls)
        else:
            cls = 'Tag.' + cls
        return 'Tag(%r%s, cls=%s)' % (self.tag,
                                      ', constructed=True' if self.constructed else '',
                                      cls)

for (n, v) in Tag._universal_tags:
    setattr(Tag, n, Tag(tag=v, constructed = (v in (0x11, 0x10)), cls = Tag.Universal))
del n, v

string_tags = (
    Tag.IA5String,
    Tag.UTF8String,
    Tag.UniversalString,
    Tag.BMPString,
    Tag.NumericString,
    Tag.PrintableString,
    Tag.VisibleString,
    Tag.TeletexString,
    Tag.VideotexString,
    Tag.GraphicString,
    Tag.GeneralString
)

class Error(Exception):
    """Exceptions raised by the Encoder and Decoder classes when called
    incorrectly (and when a specific exception such as ValueError or
    TypeError is not appropriate). This exeception usually indicates a
    programming error.
    """
    pass

class DecodeError(ValueError):
    """Raised by `Decoder` when the input data does not
    correspond to the caller's expectations, or when the input is not
    valid DER."""
    pass

class Encoder:
    """A class to encode structures according to the Distinguished Encoding Rules (DER).

    (Since DER is a restricted subset of BER, this class can also be
    used when BER-encoded data is needed.)

    """

    def __init__(self):
        self._stack = []
        self._fragments = io.BytesIO()
        self._pending_implicit = None

    def getvalue(self) -> bytes:
        """Return the accumulated encoded contents.

        It is an error to call this when any constructed types have
        been entered but not yet closed.

        """
        if len(self._stack) > 0 or self._pending_implicit is not None:
            raise Error('Unclosed constructed type')
        return self._fragments.getvalue()

    def enter(self, nr):
        """Begin constructing a constructed type. Calls to
        `enter()` must be balanced by calls to `leave()`.

        The argument is the desired ASN.1 tag, as a
        `Tag`. As a convenience, an integer is interpreted
        as a tag value in the Context class.

        """
        if isinstance(nr, int):
            self._emit_tag(nr, True, Tag.Context)
        else:
            self._emit_tag(nr.tag, True, nr.cls)
        self._stack.append(self._fragments)
        self._fragments = io.BytesIO()

    def leave(self):
        # type: () -> None
        """Finish constructing a constructed type, balancing an earlier
        call to `enter()`.
        """
        if len(self._stack) == 0:
            raise Error('Tag stack is empty.')
        if self._pending_implicit is not None:
            raise Error('Unfinished implicitly tagged object.')
        value = self._fragments.getbuffer()
        self._fragments = self._stack.pop()
        self._fragments.write(self._encode_length(len(value)))
        self._fragments.write(value)

    def enter_implicit_tag(self, nr):
        # If we already have a pending implicit tag, don't overwrite it:
        # in a situation where there are multiple implicit tags applied to
        # an object, only the outermost one actually appears in the DER
        # encoding.
        if self._pending_implicit is None:
            self._pending_implicit = Tag(nr, True, Tag.Context) if isinstance(nr, int) else nr

    def write(self, value):
        """Write one Python object to the buffer.

        If the value implements the encode_der() method, it is called
        with the encoder as the sole argument. If it implements the
        as_der() method, it is called and is expected to return a
        bytes-like object. Otherwise, the DER encoding is based on the
        value's Python type as follows:

        None          -> NULL
        True, False   -> BOOLEAN
        int           -> INTEGER
        list, tuple   -> SEQUENCE
        bytes         -> OCTET STRING
        set           -> SET
        datetime      -> GeneralizedTime

        """

        if hasattr(value, 'encode_der'):
            value.encode_der(self)
        elif hasattr(value, 'as_der'):
            assert self._pending_implicit is None
            self._fragments.write(value.as_der())
        elif value is None:
            self._emit_tag_length(Tag.Null, 0)
        elif isinstance(value, bool):
            self._emit_tag_length(Tag.Boolean, 1)
            self._fragments.write( b'\xFF' if value else b'\x00' )
        elif isinstance(value, int):
            if value == 0:
                encoded = b'\x00'  # Special case.
            else:
                if value > 0:
                    bitsize = value.bit_length()
                else:
                    bitsize = (-1 - value).bit_length()
                # We need to add one bit for the sign bit. We then
                # want to take ceil(bitsize / 8), which we can do
                # by adding 7 before dividing. So we want to add (7+1)
                # before dividing, which is equivalent to adding 1
                # after dividing.
                bytecount = ( bitsize // 8 ) + 1
                encoded = value.to_bytes(bytecount, 'big', signed=True)
                assert len(encoded) == bytecount
            self._emit_tag_length(Tag.Integer, len(encoded))
            self._fragments.write(encoded)
        elif isinstance(value, (list, tuple)):
            self.enter(Tag.Sequence)
            for elt in value:
                self.write(elt)
            self.leave()
        elif isinstance(value, set):
            self.write_set(value)
        elif isinstance(value, bytes):
            self._emit_tag_length(Tag.OctetString, len(value))
            self._fragments.write(value)
        elif isinstance(value, datetime.datetime):
            gt = self._encode_generalizedtime(value)
            self._emit_tag_length(Tag.GeneralizedTime, len(gt))
            self._fragments.write(gt)
        else:
            raise TypeError('No default encoding for type %r' % (type(value).__name__,))

    def write_tagged_bytes(self, tag: Tag, der: bytes) -> None:
        """Write a tag with arbitrary contents (supplied as a bytes object)."""
        self._emit_tag_length(tag, len(der))
        self._fragments.write(der)

    def write_raw_bytes(self, nonder: bytes) -> None:
        """Write bytes into the output stream, without any DER tagging.
        This can be used for an object that is already tagged, or
        for formats which include non-DER data in a DER container."""
        assert self._pending_implicit is None
        self._fragments.write(nonder)

    def write_set(self, values, pythontype=None):
        """Write a set of objects (a constructed object with tag SET).

        `values` may be any iterable, generator, sequence, etc., containing
        writable values. They are encoded to individual buffers, which are then
        sorted before being appended to the output, in order to produce
        canonical DER encoding."""

        self.enter(Tag.Set)
        members = list()
        content_length = 0
        for elt in values:
            if pythontype is not None:
                self.write_value_of_type(elt, pythontype)
            else:
                self.write(elt)
            fragment = self._fragments.getvalue()
            self._fragments = io.BytesIO()
            content_length += len(fragment)
            members.append(fragment)
        members.sort() # TODO: verify proper ordering
        self._fragments = self._stack.pop()
        self._fragments.write(self._encode_length(content_length))
        for elt in members:
            self._fragments.write(elt)

    def write_value_of_type(self, value, pythontype):
        """Write a value of a given ASN.1 type. The type argument should be an
        object supporting the `encode_value()` informal protocol method, or a
        tuple of such objects. Otherwise, this simply calls `write(value)`,
        which writes the value based on its runtime type.

        Writing a tuple is simply a shortcut for writing its elements: it
        does not enclose them within a SEQUENCE or other tag. For that,
        use a `Structure` or `SequenceOf` instance as the type argument.
        """

        fieldwriter = getattr(pythontype, 'encode_value', None)
        if fieldwriter is not None:
            fieldwriter(self, value)
        elif isinstance(pythontype, tuple):
            assert len(value) == len(pythontype)
            for ix in range(0, len(pythontype)):
                self.write_value_of_type(value[ix], pythontype[ix])
        else:
            self.write(value)

    def _emit_tag_length(self, tag, length):
        # type: (Tag, int) -> None
        self._emit_tag(tag.tag,
                       tag.constructed,
                       tag.cls)
        self._fragments.write(self._encode_length(length))

    def _emit_tag(self, tagnr, constructed, cls):
        # type: (int, bool, int) -> None
        if self._pending_implicit is not None:
            # Write the implicit tag instead of the actual one. But use the
            # constructed flag from the real tag.
            tagnr, cls = self._pending_implicit.tag, self._pending_implicit.cls
            self._pending_implicit = None
        t0 = (0x20 if constructed else 0) | cls
        if tagnr < 0x1F:
            self._fragments.write(bytes([ tagnr | t0 ]))
        else:
            buf = [ 0x1F | t0 , tagnr & 0x7F ]
            tagnr >>= 7
            while tagnr != 0:
                buf.insert(1, (tagnr & 0x7F) | 0x80)
                tagnr >>= 7
            self._fragments.write(bytes(buf))

    @staticmethod
    def _encode_length(length):
        # type: () -> bytes
        if length < 128:
            return bytes([length])
        else:
            # Long form: byte-count then bytes
            buf = [ ]
            while length:
                buf.insert(0, length & 0xFF)
                length >>= 8
            # really for correctness as this should not happen anytime soon
            assert len(buf) < 127
            buf.insert(0, 0x80 | len(buf))
            return bytes(buf)

    @staticmethod
    def _encode_generalizedtime(value):
        # type: (datetime.datetime) -> bytes
        tz = value.tzinfo
        if tz is not None:
            extinfo = value.strftime('%z')
            if isinstance(tz, datetime.tzinfo) and (extinfo == '-0000' or extinfo == '+0000'):
                extinfo = 'Z'
        else:
            extinfo = ''
        s = value.strftime('%Y%m%d%H%M%S')
        if value.microsecond:
            usec = '.%06d' % (value.microsecond,)
            s += usec.rstrip('0')
        s += extinfo
        return s.encode('ascii')

class Decoder:
    """A decoder of DER and (some) BER data."""

    def __init__(self, data: bytes, start=0, end=None) -> None:
        self.data = data
        self._stack = []
        self._position = start
        self._end = len(data) if end is None else end
        if self._end > start and not isinstance(data[start], int):
            raise TypeError('Expecting bytes instance.')
        self._peeked_tag = None

    def peek(self) -> Tag:
        """Returns the current ASN.1 tag as a Tag object, or None.

        Returns None at the end of input or at the end of a constructed object
        entered with enter().

        This method can be used to determine the next object's type/tag
        when decoding data with variable contents, e.g. OPTIONAL or CHOICE
        elements.

        This does not consume the tag or advance the reader past the object;
        calling it multiple times in a row will return the same value.
        """
        if self._peeked_tag is None:
            if self.eof():
                return None
            self._peeked_tag = self._read_tag()
        return self._peeked_tag

    def read_octet_string(self, tag: Tag = Tag.OctetString) -> bytes:
        """Reads an OCTET STRING from the buffer, returning its content octets as
        a bytes object, or raising DecodeError on failure.

        If the `tag` argument is set to a different tag, it will read an object
        of that type and return its content octets without further interpretation.
        """
        (_, data, pos, end) = self.read_slice(tag=tag)
        return data[pos:end]

    def read_slice(self, tag=None, optional=False):
        """Reads an object, returning the decoder's internal buffer and the
        range occupied by the object's content octets.

        This is mostly for use internally by the decoder.

        Returns a 4-tuple of (tag, buffer, startpos, endpos).

        If `tag` is specified, raises an error on tag mismatch or eof,
        unless `optional` is True, in which case None is returned
        instead.

        """

        if tag is None:
            peeked = self.peek()
            if peeked is None:
                if optional:
                    return None
                else:
                    raise DecodeError('Unexpected EOF')
        else:
            peeked = self.expect_tag(tag, optional=optional)
        if peeked is None:
            return None
        (length, pos) = self._decode_length(self.data, self._position, self._end)
        if pos+length > self._end:
            raise DecodeError('object extends %s bytes past end of buffer' % (pos+length - self._end,))
        self._position = pos+length
        self._peeked_tag = None
        return (peeked, self.data, pos, pos+length)

    def read_raw_bytes(self, bytecount: int) -> bytes:
        """Read bytes from the input without interpreting any tags.  This can
        be used for formats which include non-DER data in a DER
        container (I'm looking at you, GSSAPI).
        """
        endpos = self._position + bytecount
        if endpos > self._end:
            raise DecodeError('object extends %s bytes past end of buffer' % (endpos - self._end,))
        value = self.data[self._position : endpos]
        self._position = endpos
        return value

    def read_integer(self) -> int:
        """Reads an INTEGER and returns it as a Python `int`."""
        (_, buf, pos, end) = self.read_slice(Tag.Integer)
        if pos == end:
            return 0
        return int.from_bytes(buf[pos:end], 'big', signed=True)

    def read_boolean(self) -> bool:
        """Reads a BOOLEAN and returns it as a Python `bool`."""
        (_, buf, pos, end) = self.read_slice(Tag.Boolean)
        if pos+1 != end:
            raise DecodeError('invalid boolean (%s bytes long)' % (end-pos,))
        return buf[pos] != 0  # ITU-T X.690 [8.2]

    def read_string(self) -> str:
        """Reads any of the common string types and returns it as a Python
        unicode string.

        For details, see `decode_string()`."""
        (tag, buf, pos, end) = self.read_slice()
        if tag.cls != Tag.Universal or tag.constructed or tag.tag not in self._string_mappings:
            raise DecodeError('expecting a string type, found %s' % (tag,))
        return self.decode_string(buf[pos:end], tag.tag)

    def read_type(self, pythontype):
        """Read an object of a specified type. The type argument may be
        an object that implements `decode_der()`; or one of the built-in
        Python types bool, int, bytes, datetime, or str; or a tuple
        of types (see `Encoder.write_value_of_type()`).

        The type argument does not need to be a Python type or class; it
        may be an instance of a class such as `Structure` or `Optional`."""
        if hasattr(pythontype, 'decode_der'):
            return pythontype.decode_der(self)
        elif isinstance(pythontype, tuple):
            values = list()
            for itemtype in pythontype:
                item = self.read_type(itemtype)
                values.append(item)
            return tuple(values)
        elif pythontype == bool:
            return self.read_boolean()
        elif issubclass(pythontype, int):
            return pythontype(self.read_integer())
        elif issubclass(pythontype, bytes):
            return pythontype(self.read_octet_string())
        elif pythontype == datetime.datetime:
            return self.read_generalizedtime()
        elif pythontype == str:
            return self.read_string()
        else:
            raise TypeError("Don't know how to decode BER for type %s" % (pythontype,))

    @classmethod
    def check_readable_type(self, pythontype) -> None:
        """Tests whether an object is usable as the type argument to read_type().
        If not, raises an exception."""
        if hasattr(pythontype, 'decode_der') or \
           (pythontype in ( bool, datetime.datetime, str )) or \
           issubclass(pythontype, (int, bytes)):
            return
        raise TypeError('%s is not a der-decodable type' % (pythontype,))

    _string_mappings = {
        12: 'UTF-8', 30: 'UTF-16-BE', 28: 'UTF-32-BE',
        18: 'ascii', 19: 'ascii', 22: 'ascii', 26: 'ascii',
        20: 'T.61', 21: 'Videotex', 25: 'ISO-2022', 27: 'ISO-2022',
    }
    _t102_ascii_differences = re.compile(b'[^\\040\\041\\042\\045-\\176]') # Only for decoding, not for encoding!
    def decode_string(self, buf: bytes, tagnumber: int) -> str:
        """Decodes a string according to the syntax indicated by the tag
        number.

        TeletexString, VideotexString, PrintableString and
        GeneralString may require the availability of codecs for
        'Teletex' or 'ISO-2022'. For strings containing only ASCII
        characters, however, the decoder will simply use the ASCII
        codec.

        This method can be overridden in order to provide non-
        standard behavior (for example, if you need to be compatible with
        systems which put Latin-1 text in a TeletexString).

        """
        enc = self._string_mappings[tagnumber]
        if enc == 'T.61':
            # Teletex / T.61 / ISO-IR-102 string encoding.
            if 0x1B in buf:
                # Possibly contains invocation of other character sets.
                # Use the full ISO-2022 decoder, after setting up the
                # selection state:  G0 <- IR-102, G2 <- IR-103, C0 <- 106, C1 <- 107
                buf = b'\x1B\x28\x75\x0F\x1B\x2A\x76\x1B\x7D\x1B\x21\x45\x1B\x22\x48' + buf # T.61 initial selections
                enc = 'ISO-2022'
            elif self._t102_ascii_differences.search(buf) is None:
                # Common case: Teletex encoding of an ASCII string.
                enc = 'ascii'
        elif enc == 'Videotex':
            # Videotex / T.101 / ISO-IR-131,145,108,et al
            if self._t102_ascii_differences.search(buf) is None:
                # No bytes requiring a full Videotex decoder
                # (which is good because we probably don't have one).
                enc = 'ascii'
            else:
                #  G0 <- IR-102, C0 <- 1, C1 <- 73
                buf = b'\x1B\x28\x75\x0F\x1B\x21\x40\x1B\x22\x41' + buf # T.101 initial selections
                enc = 'ISO-2022'
        elif enc == 'ISO-2022':
            # ISO-2022 is not really an encoding itself, it's a set of
            # escape sequences for invoking other known character sets
            # and encodings like GB2312, the ISO-Latin sets,
            # JIS-X-0208, etc. If there are no escape (or delete)
            # bytes in the string, we can safely interpret it as
            # ASCII.
            if 0x1B not in buf and 0x7F not in buf:
                enc = 'ascii'
            else:
                # Otherwise, we would need to parse it for escape sequences
                # and dispatch to individual codecs. Python doesn't have a
                # general ISO-2022 decoder, oddly! But if someone wants one they
                # can install one.
                buf = b'\x1B\x28\x42\x0F\x1B\x21\x40' + buf

        return buf.decode(enc)

    def read_generalizedtime(self) -> datetime.datetime:
        """Reads a GeneralizedTime and returns it as a Python `datetime`.

        The returned datetime may be naive, if the GeneralizedTime
        contains no time zone offset; or it may have a fixed offset
        from UTC.

        """
        value = self.read_octet_string(Tag.GeneralizedTime)
        return self._decode_time(value)

    def eof(self) -> bool:
        """Test whether there is more data to be decoded.

        Returns True at the end of input, or at the end of a
        constructed object which has been entered using the enter()
        method.

        """
        assert self._position <= self._end
        return self._position == self._end

    def enter(self, tag=None, optional=False):
        """Enter the constructed type at the current decoding offet.

        If `tag` is specified, this call will fail unless the object
        to be entered has the given tag. If `optional` is False, it
        will raise a `DecodeError`; otherwise it will return None.

        `tag` may be a Tag object, or it may be a bare integer, which
        is equivalent to a CONTEXT class tag.

        It is usually an error to enter a non-constructed object, but
        `Decoder.enter()` will not prevent you from doing this, since
        there are rare situations where it is convenient.

        Returns the entered tag (a Tag instance) or None if an
        optional match failed.

        """

        if tag is None:
            peeked = self.peek()
            if peeked is None:
                raise DecodeError('Attempted to enter a subobject, but found EOF')
        else:
            peeked = self.expect_tag(tag, optional=optional)
            if peeked is None:
                return None

        (length, pos) = self._decode_length(self.data, self._position, self._end)
        nextpos = length + pos
        if nextpos > self._end:
            raise DecodeError('object extends %s bytes past end of buffer' % (nextpos - self._end,))
        self._stack.append( (nextpos, self._end) )
        self._position = pos
        self._end = nextpos
        self._peeked_tag = None
        return peeked

    def expect_tag(self, tag, optional=False):
        """Peek at the next tag and check whether it matches a specified tag.

        If the tag of the next object to be read matches `tag`, it is returned.

        Otherwise, or if the reader is at EOF, this will fail. If
        `optional` is true, it will return None on failure, otherwise
        it will raise a DecodeError with a descriptive message.

        """
        peeked = self.peek()
        if peeked is None:
            if optional:
                return None
            else:
                raise DecodeError('Expected %s, but found EOF' % (tag,))
        if isinstance(tag, int):
            if peeked.tag == tag and peeked.constructed and peeked.cls == Tag.Context:
                return peeked
        else:
            if peeked == tag:
                return peeked

        if optional:
            return None
        else:
            raise DecodeError('Expected %s, but found %s' % (tag, peeked))

    def leave(self, require_end=True) -> None:
        """Leaves the constructed type that was most recently enter()ed.

        If `require_end` is True, this will raise a DecodeError if there are more objects
        to read in the constructed object. If `require_end` is False, any unread bytes will
        be skipped.
        """
        if len(self._stack) < 1:
            raise Error('Tag stack is empty.')
        (new_pos, new_end) = self._stack.pop(-1)
        if require_end and new_pos > self._position:
            raise DecodeError('Unexpected trailing data at end of object (%s bytes)' % (new_pos - self._position,))
        assert new_pos >= self._position
        self._position = new_pos
        self._end = new_end
        self._peeked_tag = None

    def enter_implicit_tag(self, outer, inner, optional=False):
        peeked = self.expect_tag(outer, optional=optional)
        if peeked is None:
            return None
        assert self._peeked_tag is not None
        self._peeked_tag = Tag(tag=inner.tag,
                               constructed=self._peeked_tag.constructed,
                               cls=inner.cls)
        return peeked

    def _read_tag(self) -> Tag:
        """Read a tag from the input."""
        try:
            byte = self.data[self._position]
            pos = self._position + 1
            cls = byte & 0xc0
            constructed = ( byte & 0x20 ) != 0
            nr = byte & 0x1f
            if nr == 0x1f:  # Long form of tag encoding
                nr = 0
                while True:
                    byte = self.data[pos]
                    pos += 1
                    nr = (nr << 7) | (byte & 0x7f)
                    if (byte & 0x80) == 0:
                        break
        except IndexError as e:
            raise DecodeError('Truncated object') from e
        if pos >= self._end:
            raise DecodeError('Truncated object')
        self._position = pos
        return Tag(tag=nr, constructed=constructed, cls=cls)

    @staticmethod
    def _decode_length(buf: bytes, pos: int, end: int):
        """Parse a tag's length field from ``buf[pos:end]``"""
        if not (pos < end):
            raise DecodeError('Truncated object')
        byte = buf[pos]
        pos += 1
        if byte & 0x80:
            count = byte & 0x7f
            if count == 0x7f:
                raise DecodeError('ASN1 syntax error')
            elif count == 0:
                raise DecodeError('Unsupported indefinite-length encoding found')
            if pos + count > end:
                raise DecodeError('Truncated object')
            length = int.from_bytes(buf[pos:pos+count], 'big', signed=False)
            pos += count
        else:
            length = byte
        return (length, pos)

    @staticmethod
    def _decode_timezone(value: bytes):
        if value.endswith(b'Z'):
            return (value[:-1], datetime.timezone.utc)
        elif len(value) > 5 and value[-5] in b'+-':
            tzdelta = datetime.timedelta(hours=int(value[-4:-2]),
                                         minutes=int(value[-2:]))
            if value[-5] == 0x2D:
                tzdelta = -tzdelta
            return (value[:-5], datetime.timezone(tzdelta))
        else:
            return (value, None)

    @staticmethod
    def _decode_time(value: bytes) -> datetime.datetime:
        if len(value) < 10:
            raise DecodeError('Invalid GeneralizedTime')
        (value, tz) = Decoder._decode_timezone(value)

        # The time string (with the timezone removed) has the format:
        # YYYYmmddHH[MM[SS[(.|,)ffffff]]]
        # with at most six 'f's.

        if (len(value) <= 14 and len(value) not in (10, 12, 14)) or \
           (len(value) > 14 and (len(value) < 15 or value[14] not in (0x2E, 0x2C))) or \
           len(value) > 21:
            raise DecodeError('Invalid GeneralizedTime')

        yyyy = int(value[0:4])
        mm   = int(value[4:6])
        dd   = int(value[6:8])
        HH   = int(value[8:10])
        MM   = 0
        SS   = 0
        usec = 0
        if len(value) > 10:
            MM = int(value[10:12])
        if len(value) > 12:
            SS = int(value[12:14])
        if len(value) > 15:
            fraction = value[15:]
            assert len(fraction) <= 6
            usec = int( (fraction + b'000000')[:6] )

        return datetime.datetime(yyyy, mm, dd, HH, MM, SS, usec,
                                 tzinfo=tz)



class Oid:
    """Represents an object identifier (a sequence of integers).

    Oids are hashable, comparable, and can be used as dictionary keys.
    
    """
    
    __slots__ = ('_der', '_arcs')

    def __init__(self, oid):
        """An Oid can be created from a list or tuple of integers, from a
        unicode string containing the usual dotted-decimal
        representation, or from a bytes object containing the OID's
        DER representation.

        """
        
        if isinstance(oid, list):
            oid = tuple(oid)
        elif isinstance(oid, str) and '.' in oid:
            if oid.startswith('{') and oid.endswith('}'):
                oid = oid[1:-1]
            oid = tuple(int(k) for k in oid.split('.'))

        if isinstance(oid, tuple):
            self._arcs = oid
            self._der  = None
        elif isinstance(oid, bytes):
            self._valid_header(oid)
            self._der  = oid
            self._arcs = None
        else:
            raise ValueError('invalid OID')

    def as_der(self) -> bytes:
        "Returns the DER representation of the receiver."
        if self._der is None:
            self._der = self.make_der(self._arcs)
        return self._der
        
    def arcs(self):
        "The receiver as a tuple of integers."
        if self._arcs is None:
            self._arcs = self.parse_der(self._der)
        return self._arcs

    def __hash__(self):
        return self.as_der().__hash__()
    def __eq__(self, other):
        return self.as_der() == other.as_der()
    def __lt__(self, other):
        return self.arcs() < other.arcs()

    def __str__(self):
        return '.'.join(map(str, self.arcs()))
    def __repr__(self):
        return 'Oid(' + repr(self.arcs()) + ')'

    def __add__(self, r):
        """Constructs a new OID formed by appending a sequence of integers
        to the receiver."""
        r = tuple(r)
        if not all(isinstance(k, int) for k in r):
            raise TypeError('addend must be a tuple of integers')
        return self.__class__(self.arcs() + r)

    @classmethod
    def decode_der(kls, decoder):
        body = decoder.read_octet_string(tag=Tag.ObjectIdentifier)
        return kls(kls.parse_der(body, tl=False))

    @staticmethod
    def decodes_der_tag(tag):
        return tag == Tag.ObjectIdentifier

    @staticmethod
    def make_der(arcs, tl=True) -> bytes:
        """Construct the DER representation of an OID, given as a sequence of
        integers. If tl is False, the tag and length are not included and only
        the raw (inner) representation is returned.

        """
        if len(arcs) < 2 or arcs[1] >= 40:
            raise ValueError('invalid OID')
        buf = [ arcs[0] * 40 + arcs[1] ]
        for arc in arcs[2:]:
            loc = len(buf)
            buf.append(arc & 0x7F)
            arc = arc >> 7
            while arc:
                buf.insert(loc, (arc & 0x7F) | 0x80)
                arc = arc >> 7
        encoded = bytes(buf)
        if tl:
            return b'\x06' + Encoder._encode_length(len(encoded)) + encoded
        else:
            return encoded

    @staticmethod
    def _valid_header(d: bytes) -> int:
        if len(d) < 2 or d[0] != 0x06:
            raise DecodeError('Not a DER-encoded OID')
        (olen, pos) = Decoder._decode_length(d, 1, len(d))
        if pos + olen != len(d):
            raise DecodeError('Incorrect OID header')
        return pos

    @staticmethod
    def parse_der(d: bytes, tl=True):
        """Parse a DER-represented OID into a tuple of integers."""
        if tl:
            pos = Oid._valid_header(d)
        else:
            pos = 0
        try:
            byte = d[pos]
            pos += 1
            arcs = [ byte // 40, byte % 40 ]
            val = 0
            while pos < len(d):
                byte = d[pos]
                pos += 1
                if (byte & 0x80) == 0:
                    arcs.append(val | byte)
                    val = 0
                else:
                    val = ( val | (byte & 0x7F) ) << 7
                    if val == 0:
                        raise DecodeError('non-DER OID encoding')
        except IndexError as exc:
            raise DecodeError('truncated OID') from exc
        return tuple(arcs)

class OptionFlagSet:

    def __init__(self, name, bits, min_width=0):
        self.name = name
        self.bit_names = dict( (b,a) for (a,b) in bits )
        self.name_bits = dict(bits)
        self.min_width = min_width

    def decode_der(self, decoder):
        ( _, buf, pos, end ) = decoder.read_slice(Tag.BitString)
        if pos+1 > end:
            raise DecodeError('Truncated BitString')
        padding = buf[pos]
        pos += 1
        if padding > 7 or (pos == end and padding != 0):
            # ITU-T X.690 [8.6.2.2], [8.6.2.3]
            raise DecodeError('Invalid BitString padding')
        bits_set = set()
        for byteIndex in range (0, end - pos):
            b = buf[pos + byteIndex]
            if b != 0:
                for bit in range (0, 8):
                    if b & (1 << bit) != 0:
                        bitIndex = (8*byteIndex) + (7 - bit)
                        bits_set.add(self.bit_names.get(bitIndex, bitIndex))
        return bits_set

    def make_der(self, bits_set, tl=False) -> bytes:

        bytevalues = []

        (min_bytes, min_bits_in_last_byte) = divmod(self.min_width, 8)
        if min_bits_in_last_byte > 0:
            min_bytes += 1
            max_padding_in_last_byte = 8 - min_bits_in_last_byte
        else:
            max_padding_in_last_byte = 0
        if min_bytes > 0:
            bytevalues.extend(0 for i in range(0, min_bytes))

        # Set bits in a number vector
        for item in bits_set:
            if not isinstance(item, int):
                item = self.name_bits[item]
            (byteIndex, bitIndex) = divmod(item, 8)
            if len(bytevalues) <= byteIndex:
                bytevalues.extend(0 for i in range(len(bytevalues), byteIndex+1))
            bytevalues[byteIndex] |= (1 << (7 - bitIndex))

        # Compute the value of the padding octet
        if len(bytevalues) > 0:
            lastbyte = bytevalues[-1]
            if lastbyte == 0:
                assert len(bytevalues) == min_bytes
                padding = max_padding_in_last_byte
            else:
                # old trick to extract the last 1-bit in the value
                padding = {
                    0x1: 0, 0x2: 1, 0x4: 2, 0x8: 3,
                    0x10: 4, 0x20: 5, 0x40: 6, 0x80: 7,
                }[ lastbyte & ~(lastbyte-1) ];

                if len(bytevalues) == min_bytes and padding > max_padding_in_last_byte:
                    padding = max_padding_in_last_byte
            bytevalues.insert(0, padding)
            dervalue = bytes(bytevalues)
        else:
            dervalue = b'\x00'

        if tl:
            return b'\x03' + Encoder._encode_length(len(dervalue)) + dervalue
        else:
            return dervalue

class SequenceOf:
    def __init__(self, itemtype, tag=Tag.Sequence):
        Decoder.check_readable_type(itemtype)
        self.tag = tag
        self.itemtype = itemtype
        self.has_writer = hasattr(itemtype, 'encode_value')

    def decodes_der_tag(self, tag: Tag) -> bool:
        return tag == self.tag

    def decode_der(self, decoder):
        decoder.enter(self.tag)
        items = list()
        decode_der_impl = getattr(self.itemtype, 'decode_der', None)
        if decode_der_impl is None:
            while not decoder.eof():
                items.append(decoder.read_type(self.itemtype))
        else:
            while not decoder.eof():
                items.append(decode_der_impl(decoder))
        decoder.leave()
        return items

    def encode_value(self, encoder, value):
        encoder.enter(self.tag)
        for item in value:
            if self.has_writer:
                self.itemtype.encode_value(encoder, item)
            else:
                encoder.write(item)
        encoder.leave()

class Structure:
    def __init__(self, fields, tag=Tag.Sequence):
        fields = tuple(fields)
        for field in fields:
            Decoder.check_readable_type(field)
        self.tag = tag
        self.fields = fields
        self.fieldwriters = tuple(getattr(f, 'encode_value', None) for f in fields)

    def decodes_der_tag(self, tag: Tag) -> bool:
        return tag == self.tag

    def decode_der(self, decoder):
        decoder.enter(self.tag)
        items = list()
        for itemtype in self.fields:
            item = decoder.read_type(itemtype)
            items.append(item)
        decoder.leave()
        return tuple(items)

    def encode_value(self, encoder, value):
        if len(value) != len(self.fields):
            raise ValueError('Mismatched structure lengths')
        encoder.enter(self.tag)
        for ix in range(0, len(self.fields)):
            if self.fieldwriters[ix] is not None:
                self.fieldwriters[ix](encoder, value[ix])
            else:
                encoder.write(value[ix])
        encoder.leave()

class ExplicitlyTagged:
    def __init__(self, tag, itemtype):
        if isinstance(tag, int):
            tag = Tag(tag, True, Tag.Context)
        Decoder.check_readable_type(itemtype)
        self.tag = tag
        self.itemtype = itemtype
        self.has_writer = hasattr(itemtype, 'encode_value')

    def decodes_der_tag(self, tag: Tag) -> bool:
        return tag == self.tag

    def decode_der(self, decoder):
        decoder.enter(self.tag)
        value = decoder.read_type(self.itemtype)
        decoder.leave()
        return value

    def encode_value(self, encoder, value):
        encoder.enter(self.tag)
        if self.has_writer:
            self.itemtype.encode_value(encoder, value)
        else:
            encoder.write(value)
        encoder.leave()

class Optional:
    def __init__(self, itemtype):
        if itemtype in ( None, type(None) ):
            raise TypeError("That won't work, because we use the None value to indicate the absence of an optional value.")
        if hasattr(itemtype, 'decode_der') and hasattr(itemtype, 'decodes_der_tag'):
            self.lookaside = False
            self.has_writer = hasattr(itemtype, 'encode_value')
        elif isinstance(itemtype, type) and issubclass(itemtype, lookaside_types):
            self.lookaside = True
            self.has_writer = False
        else:
            raise TypeError('%s does not implement decode_der() and decodes_der_tag()' % (itemtype,))
        self.itemtype = itemtype

    def decode_der(self, decoder):
        next_tag = decoder.peek()
        if self.lookaside:
            if not lookaside_decodes_der_tag(self.itemtype, next_tag):
                return None
            return decoder.read_type(self.itemtype)
        else:
            if not self.itemtype.decodes_der_tag(next_tag):
                return None
            return self.itemtype.decode_der(decoder)

    def encode_value(self, encoder, value):
        if value is None:
            return
        elif self.has_writer:
            self.itemtype.encode_value(encoder, value)
        else:
            encoder.write(value)

class Choice:
    def __init__(self, types):
        self.types = types
    def decodes_der_tag(self, tag):
        return any(lookaside_decodes_der_tag(t, tag) for t in self.types)
    def decode_der(self, decoder):
        peeked = decoder.peek()
        for t in self.types:
            if lookaside_decodes_der_tag(t, peeked):
                return decoder.read_type(t)
        raise DecodeError('No CHOICE element starts with %r' % (peeked,))

lookaside_types = ( bool, int, bytes, datetime.datetime, str )
def lookaside_decodes_der_tag(pythontype, tag: Tag) -> bool:
    method = getattr(pythontype, 'decodes_der_tag', None)
    if method is not None:
        return method(tag)
    if pythontype == bool:
        return tag == Tag.Boolean
    elif issubclass(pythontype, int):
        return tag == Tag.Integer
    elif issubclass(pythontype, bytes):
        return tag == Tag.OctetString
    elif pythontype == datetime.datetime:
        return tag == Tag.GeneralizedTime
    elif pythontype == str:
        return tag.constructed == False and tag.cls == Tag.Universal and tag.tag in Decoder._string_mappings
    else:
        raise ValueError('No tag discriminator for type %r' % (repr(pythontype),))

