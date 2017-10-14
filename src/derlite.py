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

import collections, datetime, io, re

__version__ = "0.1.0"

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

    def __new__(self, tag, constructed=False, cls=0x00):
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
    pass

class DecodeError(ValueError):
    pass
    
class Encoder:
    """A class to encode structures according to the Distinguished Encoding Rules (DER).

    (Since DER is a restricted subset of BER, this class can also be
    used when BER-encoded data is needed.)

    """

    def __init__(self):
        self.stack = []
        self.fragments = io.BytesIO()

    def getvalue(self):
        """Return the accumulated encoded contents.

        It is an error to call this when any constructed types have
        been entered but not yet closed.

        """
        if len(self.stack) > 0:
            raise Error('Unclosed constructed type')
        return self.fragments.getvalue()
        
    def enter(self, nr):
        """Begin constructing a constructed type. Calls to enter() must
        be balanced by calls to leave().

        Argument:
            nr (int or Tag): The desired ASN.1 tag number. An integer is
            interpreted as a tag value in the Context class.
        """
        if isinstance(nr, int):
            cls = Tag.Context
        else:
            cls = nr.cls
            nr = nr.tag
        self._emit_tag(nr, True, cls)
        self.stack.append(self.fragments)
        self.fragments = io.BytesIO()

    def leave(self):
        """Finish constructing a constructed type, balancing an earlier
        call to enter().
        """
        if len(self.stack) == 0:
            raise Error('Tag stack is empty.')
        value = self.fragments.getbuffer()
        self.fragments = self.stack.pop()
        self.fragments.write(self._encode_length(len(value)))
        self.fragments.write(value)

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
            self.fragments.write(value.as_der())
        elif value is None:
            self._emit_tag_length(Tag.Null, 0)
        elif isinstance(value, bool):
            self._emit_tag_length(Tag.Boolean, 1)
            self.fragments.write( b'\xFF' if value else b'\x00' )
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
            self.fragments.write(encoded)
        elif isinstance(value, (list, tuple)):
            self.enter(Tag.Sequence)
            for elt in value:
                self.write(elt)
            self.leave()
        elif isinstance(value, set):
            self.write_set(value)
        elif isinstance(value, bytes):
            self._emit_tag_length(Tag.OctetString, len(value))
            self.fragments.write(value)
        elif isinstance(value, datetime.datetime):
            gt = self._encode_generalizedtime(value)
            self._emit_tag_length(Tag.GeneralizedTime, len(gt))
            self.fragments.write(gt)
        else:
            raise TypeError('No default encoding for type %r' % (type(value).__name__,))

    def write_value(self, tag, der):
        """Write a tag with arbitrary contents (supplied as a bytes object)."""
        self._emit_tag_length(tag, len(der))
        self.fragments.write(der)

    def write_set(self, values):
        """Write a set of objects (a constructed object with tag SET).

        `values` may be any iterable, generator, sequence, etc., containing
        writable values. They are encoded to individual buffers, which are then
        sorted before being appended to the output, in order to produce
        canonical DER encoding."""
        
        self.enter(Tag.Set)
        members = list()
        content_length = 0
        for elt in values:
            self.write(elt)
            fragment = self.fragments.getvalue()
            self.fragments = io.BytesIO()
            content_length += len(fragment)
            members.append(fragment)
        members.sort() # TODO: verify proper ordering
        self.fragments = self.stack.pop()
        self.fragments.write(self._encode_length(content_length))
        for elt in members:
            self.fragments.write(elt)

    def _emit_tag_length(self, tag, length):
        self._emit_tag(tag.tag,
                       tag.constructed,
                       tag.cls)
        self.fragments.write(self._encode_length(length))

    def _emit_tag(self, tagnr, constructed, cls):
        t0 = (0x20 if constructed else 0) | cls
        if tagnr < 0x1F:
            self.fragments.write(bytes([ tagnr | t0 ]))
        else:
            buf = [ 0x1F | t0 , tagnr & 0x7F ]
            tagnr >>= 7
            while tagnr != 0:
                buf.insert(1, (tagnr & 0x7F) | 0x80)
                tagnr >>= 7
            self.fragments.write(bytes(buf))

    @staticmethod
    def _encode_length(length):
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

    def __init__(self, data):
        if not isinstance(data, bytes):
            raise TypeError('Expecting bytes instance.')
        self.data = data
        self._stack = []
        self._position = 0
        self._end = len(data)
        self._peeked_tag = None

    def peek(self):
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

    def read_octet_string(self, tag=Tag.OctetString):
        """Reads an OCTET STRING from the buffer, returning its content octets as
        a bytes object, or raising DecodeError on failure.

        If the `tag` argument is set to a different tag, it will read an object
        of that type and return its content octets without further interpretation.
        """
        self.expect_tag(tag)
        (length, pos) = self._decode_length(self.data, self._position, self._end)
        if pos+length > self._end:
            raise DecodeError('object extends %s bytes past end of buffer' % (pos+length - self._end,))
        self._position = pos+length
        self._peeked_tag = None
        return self.data[pos : pos+length]
    
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
            if peeked is None and not optional:
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

    def read_integer(self):
        """Reads an INTEGER and returns it as a Python `int`."""
        buf = self.read_octet_string(Tag.Integer)
        if len(buf) == 0:
            return 0
        return int.from_bytes(buf, 'big', signed=True)

    def read_boolean(self):
        """Reads a BOOLEAN and returns it as a Python `bool`."""
        (_, buf, pos, end) = self.read_slice(Tag.Boolean)
        if pos+1 != end:
            raise DecodeError('invalid boolean (%s bytes long)' % (end-pos,))
        return buf[pos] != 0  # ITU-T X.690 [8.2]

    def read_string(self):
        """Reads any of the common string types and returns it as a Python
        unicode string.

        For details, see `decode_string()`."""
        (tag, buf, pos, end) = self.read_slice()
        if tag.cls != Tag.Universal or tag.constructed or tag.tag not in self._string_mappings:
            raise DecodeError('expecting a string type, found %s' % (peeked,))
        return self.decode_string(buf[pos:end], tag.tag)

    _string_mappings = {
        12: 'UTF-8', 30: 'UTF-16-BE', 28: 'UTF-32-BE',
        18: 'ascii', 19: 'ascii', 22: 'ascii', 26: 'ascii',
        20: 'T.61', 21: 'Videotex', 25: 'ISO-2022', 27: 'ISO-2022',
    }
    _t102_ascii_differences = re.compile(b'[^\\040\\041\\042\\045-\\176]') # Only for decoding, not for encoding!
    def decode_string(self, buf, tagnumber):
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
    
    def read_generalizedtime(self):
        """Reads a GeneralizedTime and returns it as a Python `datetime`.

        The returned datetime may be naive, if the GeneralizedTime
        contains no time zone offset; or it may have a fixed offset
        from UTC.

        """
        value = self.read_octet_string(Tag.GeneralizedTime)
        return self._decode_time(value)

    def eof(self):
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

        (length, self._position) = self._decode_length(self.data, self._position, self._end)
        self._stack.append( (self._position + length, self._end) )
        self._end = self._position + length
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
    
    def leave(self, require_end=True):
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

    def _read_tag(self):
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
            raise DecodeError('Truncated object') # from e
        if pos >= self._end:
            raise DecodeError('Truncated object')
        self._position = pos
        return Tag(tag=nr, constructed=constructed, cls=cls)

    @staticmethod
    def _decode_length(buf, pos, end):
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
    def _decode_timezone(value):
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
    def _decode_time(value):
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

    def as_der(self):
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
    def make_der(arcs, tl=True):
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
        buf = bytes(buf)
        if tl:
            return b'\x06' + Encoder._encode_length(len(buf)) + buf
        else:
            return buf

    @staticmethod
    def _valid_header(d):
        if d[0] != 0x06:
            raise DecodeError('Not a DER-encoded OID')
        (olen, pos) = Decoder._decode_length(d, 1, len(d))
        if pos + olen != len(d):
            raise DecodeError('Incorrect OID header')
        return pos

    @staticmethod
    def parse_der(d, tl=True):
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
            raise DecodeError('truncated OID')
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
            raise derlite.DecodeError('Truncated BitString')
        padding = buf[pos]
        pos += 1
        if padding > 7 or (pos == end and padding != 0):
            # ITU-T X.690 [8.6.2.2], [8.6.2.3]
            raise derlite.DecodeError('Invalid BitString padding')
        bits_set = set()
        for byteIndex in range (0, end - pos):
            b = buf[pos + byteIndex]
            if b != 0:
                for bit in range (0, 8):
                    if b & (1 << bit) != 0:
                        bitIndex = (8*byteIndex) + (7 - bit)
                        bits_set.add(self.bit_names.get(bitIndex, bitIndex))
        return bits_set

    def make_der(self, bits_set, tl=False):

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

