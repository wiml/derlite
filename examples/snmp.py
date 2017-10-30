import random, socket
import derlite
from derlite import Tag, Oid, SequenceOf, Structure, Choice

# This is an example of using DERlite to implement a BER-based
# protocol, SNMPv2. This shows the use of type objects to define
# parts of the message format and explicit coding to define other
# parts.


# This class cluster implements all of the SNMP-specific data types
# that appear in a variable binding (TimeTicks, gauges, etc), referred
# to in the RFCs as the ApplicationSyntax type.
class SNMPType:
    application_tag = None
    inner_tag = None
    inner_type = None

    def __init__(self, v):
        self.value = v
    def __repr__(self):
        return '%s(%r)' % ( self.__class__.__name__, self.value )
    
    # Encoding support for instances
    def encode_der(self, encoder):
        encoder.enter_implicit_tag(Tag(self.application_tag, False, cls=Tag.Application))
        self.write_value_of_type(self.value, self.inner_type)

    # Decoding support. We rely on the Choice type to dispatch to the
    # correct subclass. Alternatively we could do that here.
    @classmethod
    def decodes_der_tag(class_, tag):
        return tag.tag == class_.application_tag and tag.cls == Tag.Application
    @classmethod
    def decode_der(class_, decoder):
        decoder.enter_implicit_tag(Tag(class_.application_tag, False, cls=Tag.Application),
                                   class_.inner_tag)
        return class_(decoder.read_type(class_.inner_type))

# Concrete classes contain the mapping between tags and types.
class IpAddress (SNMPType):
    application_tag, inner_tag, inner_type = 0, Tag.OctetString, bytes
class Counter32 (SNMPType):
    application_tag, inner_tag, inner_type = 1, Tag.Integer, int
class Gauge32 (SNMPType):
    application_tag, inner_tag, inner_type = 2, Tag.Integer, int
Unsigned32 = Gauge32
class TimeTicks (SNMPType):
    application_tag, inner_tag, inner_type = 3, Tag.Integer, int
class Opaque (SNMPType):
    application_tag, inner_tag, inner_type = 4, Tag.OctetString, bytes
class NSAPAddress (SNMPType):
    application_tag, inner_tag, inner_type = 5, Tag.OctetString, bytes
class Counter64 (SNMPType):
    application_tag, inner_tag, inner_type = 6, Tag.Integer, int
class Unsigned32 (SNMPType):
    application_tag, inner_tag, inner_type = 7, Tag.Integer, int

# This class implements the various non-value values that can appear
# in a variable binding. They are all NULLs, with tagging to
# indicate the reason for the missing value.
class MissingValue:
    tag = Tag.Null
    other_tags = {
        0: 'noSuchObject',
        1: 'noSuchInstance',
        2: 'endOfMibView',
    }
    def encode_der(self, encoder):
        encoder.write_tagged_bytes(self.tag, b'')
    @classmethod
    def decodes_der_tag(class_, tag):
        if tag == Tag.Null:
            return True
        if tag.cls == Tag.Context and not tag.constructed:
            return tag.tag in class_.other_tags
        return False
    @classmethod
    def decode_der(class_, decoder):
        (tag, buf, _, _) = decoder.read_slice()
        result = class_()
        result.tag = tag
        return result
    def __repr__(self):
        if self.tag == Tag.Null:
            return 'unSpecified'
        else:
            return self.other_tags[self.tag.tag]

# The "ObjectSyntax" type is a union of SimpleSyntax (which, aside
# from the bit-set type, is represented by existing Python or DERlite
# types) and ApplicationSyntax (misc subclasses of SNMPType) types.
ObjectSyntax = Choice( ( int, bytes, Oid, # Also bit-strings
                         IpAddress, Counter32, Gauge32,
                         TimeTicks, Opaque, NSAPAddress,
                         Counter64, Unsigned32 ) )

# This is called a PDU in RFC1448/RFC1905/RFC3416, although it isn't a
# PDU in the usual sense of being the contents of a message --- it's
# wrapped in something else, depending on the SNMP version.
class PDU:
    _concrete_type = Structure(
        ( int, int, int,
          SequenceOf(
              Structure(
                  (Oid, Choice((ObjectSyntax, MissingValue)))
              )
          )
        )
    )
    
    def __init__(self, pdu_type, request_id=None):
        self.pdu_type = pdu_type
        if request_id is None:
            request_id = int(random.uniform(0, 2**31))
        self.request_id = request_id
        self.error_status = 0
        self.error_index = 0
        self.bindings = []

    @classmethod
    def decode_der(class_, decoder):
        peeked = decoder.peek()
        if peeked.constructed and peeked.cls == Tag.Context:
            decoder.enter_implicit_tag(peeked, Tag.Sequence)
        fields = class_._concrete_type.decode_der(decoder)
        pdu = class_(peeked, request_id=fields[0])
        ( _, pdu.error_status, pdu.error_index, pdu.bindings ) = fields
        return pdu
        
    def encode_der(self, encoder):
        if self.pdu_type is not None:
            encoder.enter_implicit_tag(self.pdu_type)
        encoder.write_value_of_type( (self.request_id, self.error_status, self.error_index, self.bindings), self._concrete_type )

    def debug_print(self, indent=''):
        if self.pdu_type is not None:
            print(indent+"type:", self.pdu_type)
        print(indent+"request_id:", self.request_id)
        print(indent+"error_status:", self.error_status)
        print(indent+"error_index:", self.error_index)
        print(indent+"Bindings:", len(self.bindings))
        for (var_oid, var_value) in self.bindings:
            print(indent+"  ", var_oid)
            print(indent+"    ", var_value)

# A v2c datagram contains a "PDU", along with a version number and
# community string.
def encode_v2c_message(community, pdu):
    enc = derlite.Encoder()
    enc.enter(Tag.Sequence)
    enc.write(1)  # constant 1 = SNMPv2
    if not isinstance(community, bytes):
        enc.write(community.encode('utf-8'))
    else:
        enc.write(community)
    enc.enter_implicit_tag(0)
    pdu.encode_der(enc)
    enc.leave()  # matches opening Sequence
    return enc.getvalue()

def decode_v2c_message(dgram):
    dec = derlite.Decoder(dgram)
    dec.enter(Tag.Sequence)
    vnum = dec.read_integer()
    if vnum != 1:
        raise derlite.DecodeError('Not a SNMPv2 datagram!')
    community = dec.read_octet_string()
    pdu = dec.read_type(PDU)
    dec.leave()
    return (community, pdu)

# The main function: given an agent to query and some
# OIDs of interest, construct a GET request, send it,
# parse the response, and print it.
def query_variables(socket, agent, community, *oids):

    # Create the request
    query_message = PDU(0)
    for oid in oids:
        query_message.bindings.append( (oid, None) )
    query_message.debug_print()

    # Send it
    socket.sendto(encode_v2c_message(community, query_message),
                  0,
                  (agent, 161))

    print("\nWaiting for response...")
    
    while True:
        (dgram, fromaddr) = socket.recvfrom(8192)
        print("\nDatagram from", fromaddr)
        decoder = derlite.Decoder(dgram)
        (resp_community, resp_pdu) = decode_v2c_message(dgram)
        print("Community:", resp_community)
        print("Response:", resp_pdu)
        resp_pdu.debug_print(indent='  ')
        if community == resp_community and query_message.request_id == resp_pdu.request_id:
            break

# Some useful OIDs
snmp_mib_2 = Oid('1.3.6.1.2.1')       # The MIB-II oid
snmp_system_group = snmp_mib_2 + (1,) # The 'system' group from RFC1213

# Perform a simple SNMP query. We ask for three OIDs:
# MIB-II.system.sysDescr.0 and .1, and MIB-II.system.sysUpTime.0.
# The trailing 0 refers to the value of the object, more or less
# (see RFC1212 [4.1.6]). So we expect sysDescr.0 and sysUpTime.0 to
# succeed, but sysDescr.1 to fail since there is only one value
# for sysDescr; it's a scalar object not a table.
query_variables(socket.socket(socket.AF_INET, socket.SOCK_DGRAM),
                '127.0.0.1',   # Agent address
                b'public',     # Community string
                snmp_mib_base + (1,0),  # sysDescr.0
                snmp_mib_base + (1,1),  # sysDescr.1
                snmp_mib_base + (3,0),  # sysUpTime.0
)

