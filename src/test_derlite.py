
import derlite
import datetime
import unittest

class Test (unittest.TestCase):

    def around(self, enc, der):
        der = bytes.fromhex(der)
        got = enc.getvalue()
        self.assertEqual(got, der)
        return derlite.Decoder(got)

    def test_simple_values(self):

        enc = derlite.Encoder()
        enc.write(1)
        enc.write(True)
        enc.write(b'\x00\x42\xFE')

        dec = self.around(enc, '020101 0101FF 04030042FE')
        self.assertFalse(dec.eof())
        self.assertEqual(dec.read_integer(), 1)
        self.assertEqual(dec.read_boolean(), True)
        self.assertEqual(dec.peek(), derlite.Tag.OctetString)
        self.assertEqual(dec.read_octet_string(), b'\x00\x42\xFE')
        self.assertEqual(dec.peek(), None)
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
    
