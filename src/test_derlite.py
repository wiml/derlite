
import derlite
from derlite import Tag, Oid, DecodeError

import codecs, datetime, unittest

try:
    codecs.lookup('Teletex')
    teletex_available = True
except LookupError:
    teletex_available = False

class Test (unittest.TestCase):

    def around(self, enc, der):
        der = bytes.fromhex(der)
        got = enc.getvalue()
        self.assertEqual(got, der)
        return derlite.Decoder(got)

    def test_simple_values(self):

        # Test round-tripping some simple values, and some of the
        # decoder status methods.
        enc = derlite.Encoder()
        enc.write(1)
        enc.write(True)
        enc.write(b'\x00\x42\xFE')

        dec = self.around(enc, '020101 0101FF 04030042FE')
        self.assertFalse(dec.eof())
        self.assertEqual(dec.read_integer(), 1)
        self.assertEqual(dec.read_boolean(), True)
        self.assertEqual(dec.peek(), Tag.OctetString)
        self.assertEqual(dec.read_octet_string(), b'\x00\x42\xFE')
        self.assertEqual(dec.peek(), None)
        self.assertTrue(dec.eof())

    def test_simple_compound(self):

        # A quick test of enter/leave
        enc = derlite.Encoder()
        enc.write(-128)
        enc.write( [ None ] )
        enc.write( [] )
        enc.write(128)

        dec = self.around(enc, '020180 30020500 3000 02020080')
        self.assertEqual(dec.read_integer(), -128)
        self.assertFalse(dec.eof())
        self.assertEqual(dec.peek(), Tag.Sequence)
        dec.enter(Tag.Sequence)
        self.assertEqual(dec.peek(), Tag.Null)
        self.assertEqual(dec.read_octet_string(Tag.Null), b'')
        self.assertTrue(dec.eof())
        self.assertIsNone(dec.peek())
        dec.leave()
        self.assertFalse(dec.eof())
        dec.enter(Tag.Sequence)
        self.assertTrue(dec.eof())
        dec.leave()
        self.assertFalse(dec.eof())
        self.assertEqual(dec.read_integer(), 128)
        self.assertTrue(dec.eof())

    def test_implicit_tagging(self):

        enc = derlite.Encoder()
        enc.enter_implicit_tag(1)
        enc.write(42)

        enc.write(1)

        enc.enter_implicit_tag(Tag(0, True, Tag.Application))
        enc.enter(Tag.Sequence)
        enc.write(b'foo')
        enc.write(b'bar')
        enc.leave()

        dec = self.around(enc,
                          '81012A 020101 600A 0403666F6F 0403626172')

        self.assertEqual(dec.peek(), Tag(1, False, Tag.Context))
        self.assertRaises(DecodeError, dec.read_integer)
        dec.enter_implicit_tag(Tag(1, False, Tag.Context), Tag.Integer)
        self.assertEqual(dec.read_integer(), 42)

        self.assertIsNone(dec.enter_implicit_tag(1, Tag.Integer, optional=True))
        self.assertEqual(dec.read_integer(), 1)

        self.assertIsNone(dec.enter(Tag.Sequence, optional=True))
        dec.enter_implicit_tag(Tag(0, True, Tag.Application),
                               Tag.Sequence)
        dec.enter(Tag.Sequence)
        self.assertEqual(dec.read_type(bytes), b'foo')
        self.assertEqual(dec.read_octet_string(), b'bar')
        self.assertRaises(DecodeError,
                          lambda:  dec.enter_implicit_tag(Tag(2, False, Tag.Context),
                                                          Tag.Sequence))
        dec.leave()
        self.assertTrue(dec.eof())

    def test_decode_failures(self):

        # An object goes past the end
        dec = derlite.Decoder(bytes.fromhex('020201'))
        self.assertRaises(DecodeError, dec.read_integer)

        # A sequence goes past the end
        dec = derlite.Decoder(bytes.fromhex('020101 3004 020101'))
        self.assertEqual(dec.read_integer(), 1)
        self.assertRaises(DecodeError, dec.enter)

        # An object goes past the end of its container
        dec = derlite.Decoder(bytes.fromhex('020101 3003 02020100'))
        self.assertEqual(dec.read_integer(), 1)
        self.assertEqual(dec.enter(), Tag.Sequence)
        self.assertRaises(DecodeError, dec.read_integer)

        dec = derlite.Decoder(bytes.fromhex('020101 3001 02020100'))
        self.assertEqual(dec.read_integer(), 1)
        self.assertEqual(dec.enter(), Tag.Sequence)
        self.assertRaises(DecodeError, dec.read_integer)

        dec = derlite.Decoder(bytes.fromhex('0282000101 3003 0282000101'))
        self.assertEqual(dec.read_integer(), 1)
        self.assertEqual(dec.enter(), Tag.Sequence)
        self.assertRaises(DecodeError, dec.read_integer)

    def test_integers(self):
        # Test correct encoding of integers of various widths
        enc = derlite.Encoder()
        enc.write(-129)
        enc.write(128)
        enc.write(-128)
        enc.write(127)
        enc.write(-1)
        enc.write(0)
        enc.write(1)
        enc.write(-127)
        enc.write(-256)
        enc.write(255)

        dec = self.around(enc,
                          '0202FF7F 02020080 020180 02017F 0201FF 020100 020101 020181 0202FF00 020200FF')
        self.assertEqual(dec.read_integer(), -129)
        self.assertEqual(dec.read_integer(),  128)
        self.assertEqual(dec.read_integer(), -128)
        self.assertEqual(dec.read_integer(),  127)
        self.assertEqual(dec.read_integer(),   -1)
        self.assertEqual(dec.read_integer(),    0)
        self.assertEqual(dec.read_integer(),    1)
        self.assertEqual(dec.read_integer(), -127)
        self.assertEqual(dec.read_integer(), -256)
        self.assertEqual(dec.read_integer(),  255)

    def test_tagobject(self):

        self.assertEqual(repr(Tag.Sequence),
                         'Tag.Sequence')
        self.assertEqual(repr(Tag(0, constructed=True, cls=Tag.Application)),
                         'Tag(0, constructed=True, cls=Tag.Application)')


    def test_tagforms(self):

        # Test encoding of tags
        enc = derlite.Encoder()
        # Tag numbers >= 31 have a different encoding
        enc.enter(31)
        enc.write_tagged_bytes(Tag(16, constructed=False, cls=Tag.Application),
                               b'      ')
        # Object lengths >= 128 bytes have a different encoding
        ablob = b'ABCDE' * 100
        enc.write_tagged_bytes(Tag(1000, constructed=False, cls=Tag.Context),
                               ablob)
        enc.leave()

        dec = self.around(enc,
                          'BF1F820202 5006202020202020' +
                          '9F87688201F4 ' +
                          ( '4142434445' * 100 ))

        self.assertIsNone(dec.enter(32, optional=True))
        self.assertEqual(dec.enter(31),
                         Tag(31, constructed=True, cls=Tag.Context))
        self.assertRaises(derlite.DecodeError, dec.read_octet_string)
        self.assertEqual(dec.read_octet_string(Tag(16, cls=Tag.Application)),
                         b'      ')
        self.assertEqual(dec.read_octet_string(Tag(1000, cls=Tag.Context)),
                         ablob)
        self.assertTrue(dec.eof())
        dec.leave()
        self.assertTrue(dec.eof())
        self.assertRaises(derlite.Error, dec.leave)

    def test_set1(self):
        # Simple test of set encoding: the DER encoder is responsible
        # for ensuring the element ordering required by DER
        enc = derlite.Encoder()
        enc.write( set([ -1, 0, 1 ]) )
        dec = self.around(enc, '3109 020100 020101 0201FF')

        dec.enter(Tag.Set)
        self.assertEqual(dec.read_integer(), 0)
        self.assertEqual(dec.read_integer(), 1)
        self.assertEqual(dec.read_integer(), -1)
        dec.leave()
        self.assertTrue(dec.eof())

    def test_set2(self):
        # More set tests
        enc = derlite.Encoder()
        enc.write_set( bytes([ 1, b ]) for b in (4, 2, 8) )
        dec = self.around(enc, '310C 04020102 04020104 04020108')

        enc = derlite.Encoder()
        enc.write_set( [ None, False, [], Oid((1, 10)), True ] )
        dec = self.around(enc, '310D 010100 0101FF 0500 060132 3000')

    def test_set3(self):
        enc = derlite.Encoder()
        enc.write_set( [ 1, 0 ],
                       pythontype=derlite.ExplicitlyTagged(0, int))
        self.assertEqual(enc.getvalue(),
                         bytes.fromhex('310A A003020100 A003020101'))

    def test_strings_1(self):
        # Test decoding some strings.

        # IA5String and UTF8String
        dec = derlite.Decoder(b'\x16\x06flambe\x0c\x07flamb\xC3\xA9')
        self.assertEqual(dec.read_string(), 'flambe')
        self.assertEqual(dec.read_string(), 'flamb\u00E9')
        self.assertTrue(dec.eof())

        # PrintableString and (simple) GeneralString.
        dec = derlite.Decoder(b'\x13\x05hello\x1B\x06world!')
        self.assertEqual(dec.read_string(), 'hello')
        self.assertEqual(dec.read_string(), 'world!')
        self.assertTrue(dec.eof())

    def test_strings_teletex_ascii(self):
        dec = derlite.Decoder(b'\x14\x1FSome parts of T.61 match ASCII.')
        self.assertEqual(dec.read_string(), 'Some parts of T.61 match ASCII.')
        self.assertTrue(dec.eof())

    @unittest.skipUnless(teletex_available,
                         "Teletex/T.61 codec is not available.")
    def test_strings_teletex(self):
        dec = derlite.Decoder(b'\x14\x03See\x14\x07\xECe Olde' +
                              b'\x14\x28\xABM\xC8uller, Fran\xCBcois, \xEArsted, l\'H\xC3opital\xBB' +
                              b'\x14\x03(\xA4)')
        self.assertEqual(dec.read_string(), 'See')
        self.assertEqual(dec.read_string(), '\u00DEe Olde')
        self.assertEqual(dec.read_string(), '\u00ABM\u00FCller, Fran\u00E7ois, \u0152rsted, l\'H\u00F4pital\u00BB')
        self.assertEqual(dec.read_string(), '($)')
        self.assertTrue(dec.eof())

    def test_bad_usage(self):

        # Trying to getvalue() when we don't have a complete object
        enc = derlite.Encoder()
        enc.enter(Tag(1, True, Tag.Application))
        enc.write(True)
        self.assertRaises(derlite.Error,
                          enc.getvalue)

        # Trying to leave() more than we enter()
        enc = derlite.Encoder()
        enc.enter(2)
        enc.write(1)
        enc.leave()
        enc.write(2)
        self.assertRaises(derlite.Error,
                          enc.leave)

        # Trying to write an unsupported type
        enc = derlite.Encoder()
        enc.write(b'foo')
        self.assertRaises(TypeError,
                          enc.write, u'bar')


class TestDatetimes (unittest.TestCase):

    def roundtrip(self, dt, der):
        enc = derlite.Encoder()
        enc.write(dt)
        got = enc.getvalue()
        self.assertEqual(got, der)

        dec = derlite.Decoder(der)
        got = dec.read_generalizedtime()
        self.assertEqual(dt, got)

    def test_naive(self):
        self.roundtrip(datetime.datetime.utcfromtimestamp(0),
                       b'\x18\x0e19700101000000' )
        self.roundtrip(datetime.datetime.utcfromtimestamp(86460.75),
                       b'\x18\x1119700102000100.75' )

    def test_utc(self):
        utc = datetime.timezone.utc
        self.roundtrip(datetime.datetime.fromtimestamp(0, utc),
                       b'\x18\x0f19700101000000Z' )
        self.roundtrip(datetime.datetime.fromtimestamp(1.25, utc),
                       b'\x18\x1219700101000001.25Z' )

        dec = derlite.Decoder( b'\x18\x0d198002010000Z' +
                               b'\x18\x0b1980020100Z' )
        self.assertEqual( datetime.datetime(1980, 2, 1, 0, 0, 0,
                                            tzinfo=utc),
                          dec.read_generalizedtime())
        self.assertEqual( datetime.datetime(1980, 2, 1, 0, 0, 0,
                                            tzinfo=utc),
                          dec.read_generalizedtime())

    def test_tzs(self):
        london = datetime.timezone(datetime.timedelta(0, 0))
        newfoundland = datetime.timezone(datetime.timedelta(hours = -3, minutes = -30))
        newcaledonia = datetime.timezone(datetime.timedelta(hours = 11))

        self.roundtrip(datetime.datetime(1980, 2, 29, 6, 45, 12,
                                         tzinfo=newfoundland),
                       b'\x18\x1319800229064512-0330')
        self.roundtrip(datetime.datetime(1988, 3, 1, 0, 5, 15,
                                         microsecond=368100,
                                         tzinfo=london),
                       b'\x18\x1419880301000515.3681Z')
        self.roundtrip(datetime.datetime(1992, 12, 31, 23, 30,
                                         tzinfo=newcaledonia),
                       b'\x18\x1319921231233000+1100')

class TestOids (unittest.TestCase):

    def roundtrip(self, arcs, der):
        o = Oid(arcs)
        self.assertEqual(o.as_der(), der)
        o = Oid(der)
        self.assertEqual(o.arcs(), arcs)

    def test_encoding(self):
        self.roundtrip( (1,2,3), b'\x06\x02\x2A\x03')
        self.roundtrip( (1,2,840,10040,4,1), b'\x06\x07\x2A\x86\x48\xCE\x38\x04\x01')
        self.roundtrip( (2,5,4,3), b'\x06\x03\x55\x04\x03')

    def test_parses(self):
        self.assertEqual(Oid( '2.5.4.3' ).as_der(),
                         b'\x06\x03\x55\x04\x03')
        self.assertEqual(Oid( '{ 1.2.840.10040.4.1 }' ).as_der(),
                          b'\x06\x07\x2A\x86\x48\xCE\x38\x04\x01')
        self.assertEqual(Oid( [ 3, 9 ] ).arcs(),
                         (3, 9))

        self.assertRaises(Exception,
                          Oid, 42)
        self.assertRaises(derlite.DecodeError,
                          Oid, b'\x03\x03\x55\x04\x03')
        self.assertRaises(derlite.DecodeError,
                          lambda x: Oid(x).arcs(),
                          b'\x06\x02\x2A\x03\x01')

    def test_misc(self):
        # Creating sub-OIDs, comparison, hashing, etc.
        self.assertEqual(str(Oid( (2,5,4,3) )),
                         '2.5.4.3')
        pkcs = Oid( '1.2.840.113549.1' )
        pkcs1 = pkcs + (1,)
        self.assertEqual(repr(pkcs1),
                         'Oid((1, 2, 840, 113549, 1, 1))')
        pkcs_ = Oid(b'\x06\x07*\x86H\x86\xf7\x0d\x01')
        self.assertEqual(pkcs, pkcs_)
        self.assertLess(pkcs_, pkcs1)
        self.assertGreater(pkcs1, pkcs)

        s = set()
        self.assertNotIn(pkcs, s)
        self.assertNotIn(pkcs_, s)
        self.assertNotIn(pkcs1, s)
        s.add(pkcs)
        self.assertIn(pkcs, s)
        self.assertIn(pkcs_, s)
        self.assertNotIn(pkcs1, s)
        s.add(pkcs_)
        self.assertEqual(len(s), 1)
        s.add(pkcs1)
        self.assertEqual(len(s), 2)
        self.assertIn(pkcs, s)
        self.assertIn(pkcs1, s)

    def test_bad_values(self):

        oid = Oid('1.2.3')
        self.assertRaises(TypeError,
                          lambda: oid + (5, 6, "bananas", 7))

        # There's no encoding for a 0- or 1-element OID.
        self.assertRaises(ValueError,
                          lambda a: Oid(a).as_der(),
                          (1,))
        self.assertRaises(ValueError,
                          lambda a: Oid(a).as_der(),
                          ())

        # The first two elements have constrained ranges because
        # of the way they're encoded.
        self.assertRaises(ValueError,
                          lambda a: Oid(a).as_der(),
                          (1000,2,3,4))
        self.assertRaises(ValueError,
                          lambda a: Oid(a).as_der(),
                          (1,50,3))

class BitSetTest (unittest.TestCase):

    def roundtrip(self, fs, flags, der):
        der = bytes.fromhex(der)
        self.assertEqual(fs.make_der(flags, tl=True), der)
        dec = derlite.Decoder(der)
        self.assertEqual(fs.decode_der(dec), flags)

    def test(self):
        fs = derlite.OptionFlagSet('foo',
                                   ( ('bob', 1),
                                     ('carol', 2),
                                     ('ted', 3),
                                     ('alice', 5) ))
        self.roundtrip(fs, set(), '03 01 00')
        self.roundtrip(fs, set(['bob']), '03 02 06 40')
        self.roundtrip(fs, set(['carol']), '03 02 05 20')
        self.roundtrip(fs, set(['bob', 'carol', 'ted', 'alice']), '03 02 02 74')
        self.roundtrip(fs, set(['alice']), '03 02 02 04')
        self.roundtrip(fs, set(['alice', 7]), '03 02 00 05')
        self.roundtrip(fs, set(['alice', 8]), '03 03 07 0480')

    @staticmethod
    def expected_padding(bitwidth):
        return 7 - ((bitwidth+7) % 8)

    def test_widths(self):
        for dw in (1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 30, 31, 32, 33):
            fs = derlite.OptionFlagSet('dw',
                                       ( ('a', 1),
                                         ('b', dw-1),
                                         ('c', dw) ),
                                       min_width = dw)

            b0 = fs.make_der([], tl=False)
            self.assertEqual(b0[0], self.expected_padding(dw))

            b1 = fs.make_der([ 'a' ], tl=False)
            self.assertEqual(b1[0], self.expected_padding(max(dw,2)))
            self.assertEqual(b1[1], 0x40)

            b2 = fs.make_der([ 'b' ], tl=False)
            self.assertEqual(b2[0], self.expected_padding(dw))
            self.assertEqual(b2[-1], 1 << (7 - ((dw-1)%8)))

            b3 = fs.make_der([ 'c' ], tl=False)
            self.assertEqual(b3[0], self.expected_padding(dw+1))
            self.assertEqual(b3[-1], 1 << (7 - (dw%8)))


class TypeCombTest (unittest.TestCase):

    def roundtrip(self, d, dt, der):
        der = bytes.fromhex(der)

        enc = derlite.Encoder()
        enc.write_value_of_type(d, dt)
        got = enc.getvalue()
        self.assertEqual(got, der)

        dec = derlite.Decoder(der)
        got = dec.read_type(dt)
        self.assertEqual(d, got)

    def test_seqs(self):

        thing = derlite.Structure(
            ( int,
              datetime.datetime,
              derlite.SequenceOf(Oid),
              bytes
            )
        )

        self.roundtrip(
            ( 1000, datetime.datetime(1969, 7, 20, 10, 56),
              [ Oid( (1, k, 10) ) for k in (0, 3, 9) ],
              b'some more stuff' ),
            thing,
            '3033'
            '020203E8'
            '180E' + bytes.hex(b'19690720105600') +
            '300C'
            '0602280A 06022B0A 0602310A'
            '040F' + bytes.hex(b'some more stuff'))

        self.roundtrip(
            ( -1, datetime.datetime(1234, 4, 5, 6, 7, 8),
              [],
              b'' ),
            thing,
            '3017'
            '0201FF'
            '180E' + bytes.hex(b'12340405060708') +
            '3000'
            '0400')

        thing = ( int, bool, bytes )
        self.roundtrip(
            ( -129, False, b'' ),
            thing,
            '0202FF7F 010100 0400')

        thing = derlite.ExplicitlyTagged(
            Tag(16, True, Tag.Application),
            derlite.Structure(
                (
                    derlite.SequenceOf(int),
                    Oid
                )
            )
        )
        self.roundtrip( ([1,2,3], Oid((1,2,3))),
                        thing,
                        '7011 '
                        '300F '
                        '3009 020101 020102 020103'
                        '06022A03')

    def test_choice(self):

        thing = derlite.SequenceOf( derlite.Choice(
            (
                int,
                Oid,
                bool,
            )
        ))

        self.roundtrip(
            [],
            thing,
            '3000')

        self.roundtrip(
            [ 42 ],
            thing,
            '3003 02012A')

        self.roundtrip(
            [ Oid('1.8.10000'), -128, False ],
            thing,
            '300B'
            '060330CE10'
            '020180'
            '010100')

        thing = derlite.Structure(
            ( derlite.Choice(
                (bytes,
                 bool,
                 derlite.Choice( (datetime.datetime, int) )
                )
            ),)
        )

        self.roundtrip(
            ( b'foo', ),
            thing,
            '3005 0403666F6F')
        self.roundtrip(
            ( 12, ),
            thing,
            '3003 02010C')
        self.roundtrip(
            ( False, ),
            thing,
            '3003 010100')

    def test_optionals(self):
        thing = derlite.Structure(
            ( int,
              derlite.Optional(derlite.ExplicitlyTagged(2, int) )
            )
        )
        self.roundtrip( (3, None), thing, '3003 020103' )
        self.roundtrip( (3, 5), thing, '3008 020103 A203 020105' )
        self.roundtrip( (0, 0), thing, '3008 020100 A203 020100' )

        thing = derlite.Structure(
            ( derlite.Optional(derlite.ExplicitlyTagged(31, bytes)),
              derlite.Optional(int)
            )
        )
        self.roundtrip( (None, None), thing, '3000' )
        self.roundtrip( (None, 1   ), thing, '3003 020101' )
        self.roundtrip( (b'A', None), thing, '3006 BF1F03 040141' )
        self.roundtrip( (b'B', 128 ), thing, '300A BF1F03 040142 02020080' )

        thing = derlite.Optional(
            derlite.Structure(
                ( int, Oid )
            )
        )
        self.roundtrip(None, thing, '')
        self.roundtrip( (4, Oid('2.1.128')), thing,
                        '3008 020104 0603518100')

