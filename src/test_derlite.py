
import derlite
import datetime
import unittest
from derlite import Tag

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
        enc.enter(31)
        enc.write_value(Tag(16, constructed=False, cls=Tag.Application),
                        b'      ')
        ablob = b'ABCDE' * 100
        enc.write_value(Tag(1000, constructed=False, cls=Tag.Context),
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
                       b'\x1b\x0e19700101000000' )
        self.roundtrip(datetime.datetime.utcfromtimestamp(86460.75),
                       b'\x1b\x1119700102000100.75' )

    def test_utc(self):
        utc = datetime.timezone.utc
        self.roundtrip(datetime.datetime.fromtimestamp(0, utc),
                       b'\x1b\x0f19700101000000Z' )
        self.roundtrip(datetime.datetime.fromtimestamp(1.25, utc),
                       b'\x1b\x1219700101000001.25Z' )
                       
        dec = derlite.Decoder( b'\x1b\x0d198002010000Z' +
                               b'\x1b\x0b1980020100Z' )
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
                       b'\x1b\x1319800229064512-0330')
        self.roundtrip(datetime.datetime(1988, 3, 1, 0, 5, 15,
                                         microsecond=368100,
                                         tzinfo=london),
                       b'\x1b\x1419880301000515.3681Z')
        self.roundtrip(datetime.datetime(1992, 12, 31, 23, 30,
                                         tzinfo=newcaledonia),
                       b'\x1b\x1319921231233000+1100')

class TestOids (unittest.TestCase):

    def roundtrip(self, arcs, der):
        o = derlite.Oid(arcs)
        self.assertEqual(o.as_der(), der)
        o = derlite.Oid(der)
        self.assertEqual(o.arcs(), arcs)

    def test_encoding(self):
        self.roundtrip( (1,2,3), b'\x06\x02\x2A\x03')
        self.roundtrip( (1,2,840,10040,4,1), b'\x06\x07\x2A\x86\x48\xCE\x38\x04\x01')
        self.roundtrip( (2,5,4,3), b'\x06\x03\x55\x04\x03')

    def test_parses(self):
        self.assertEqual(derlite.Oid( '2.5.4.3' ).as_der(),
                         b'\x06\x03\x55\x04\x03')
        self.assertEqual(derlite.Oid( '{ 1.2.840.10040.4.1 }' ).as_der(),
                          b'\x06\x07\x2A\x86\x48\xCE\x38\x04\x01')
        self.assertEqual(derlite.Oid( [ 3, 9 ] ).arcs(),
                         (3, 9))
        
        self.assertRaises(Exception,
                          derlite.Oid, 42)
        self.assertRaises(derlite.DecodeError,
                          derlite.Oid, b'\x03\x03\x55\x04\x03')
        self.assertRaises(derlite.DecodeError,
                          lambda x: derlite.Oid(x).arcs(),
                          b'\x06\x02\x2A\x03\x01')

    def test_misc(self):
        self.assertEqual(str(derlite.Oid( (2,5,4,3) )),
                         '2.5.4.3')
        pkcs = derlite.Oid( '1.2.840.113549.1' )
        pkcs1 = pkcs + (1,)
        self.assertEqual(repr(pkcs1),
                         'Oid((1, 2, 840, 113549, 1, 1))')
        pkcs_ = derlite.Oid(b'\x06\x07*\x86H\x86\xf7\x0d\x01')
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
    
