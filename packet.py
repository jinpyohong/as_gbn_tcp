from enum import IntFlag


class Seq:
    """8-bit Wrap-around sequence number"""
    MOD = 1 << 8  # 8 bit sequence number
    HALF = MOD >> 1

    def __init__(self, number):
        if not isinstance(number, int):
            raise TypeError('not int type')
        self.seq = number % Seq.MOD

    def __repr__(self): return 'Seq({})'.format(self.seq)

    def __str__(self): return str(self.seq)

    def __int__(self): return self.seq  # int conversion

    def __add__(self, n:int):
        """Forward n steps"""
        if not isinstance(n, int):
            raise TypeError('not int type')
        return Seq(self.seq + n)

    def __sub__(self, n:int):
        """Backward n steps"""
        if not isinstance(n, int):
            raise TypeError('not int type')
        return Seq(self.seq - n)

    def __eq__(self, other):
        if not isinstance(other, Seq):
            raise TypeError('not Seq type')
        return self.seq == other.seq

    def __lt__(self, other):
        if not isinstance(other, Seq):
            raise TypeError('not Seq type')
        return (self.seq < other.seq and other.seq - self.seq < Seq.HALF) or \
               (self.seq > other.seq and self.seq - other.seq > Seq.HALF)

    def __ne__(self, other): return not self.__eq__(other)

    def __ge__(self, other): return not self.__lt__(other)

    def __le__(self, other): return self.__lt__(other) or self.__eq__(other)

    def __gt__(self, other): return not self.__le__(other)


def srange(start:Seq, end:Seq):
    """Sequence range
    """
    if not (isinstance(start, Seq) and isinstance(end, Seq)):
        raise TypeError('not Seq type')
    seq = Seq(start.seq)
    while seq != end:
        yield seq
        seq += 1


class Type(IntFlag):
    """Packet type definition
    """
    DATA    = 1
    ACK     = 2
    FIN     = 4
    # SYN     = 8
    # RST     = 16
    # URG     = 32
    # PSH     = 64


class Packet:
    def __init__(self, pdu, seq=None, data=b''):
        """Make a Packet object from the raw packet(bytes or bytearray)
        or sequence, packet_type, data
            Packet(pdu)     - convert pdu(bytes/bytearray type) to Packet object
            Packet(type, seq)   - no data
            Packet(type, seq, data)

        :param pdu: bytes/bytearray or packet type
        :param seq: sequence number: int or Seq type
        :param data: data if any: bytes or bytearray
        """
        if seq is None:
            if not isinstance(pdu, (bytes, bytearray)):
                raise TypeError('pdu: not byte/bytearray type')
            self.pdu = pdu
            return
        if not isinstance(seq, (int, Seq)):
            raise TypeError('seq: not int/Seq type')
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError('data: not bytes/bytearray type')
        self.pdu = bytearray([pdu, int(seq), 0, 0])  # header clearing checksum field
        self.pdu.extend(data)
        checksum = self.ichecksum()
        self.pdu[2:4] = bytearray([checksum >> 8, checksum & 0xFF])  # put the checksum

    def __repr__(self):
        return repr(self.pdu) if len(self.pdu) <= 16 else (repr(self.pdu[:16]) + '...')

    def __str__(self):
        # try:
        #     pdu_name = Type(self.pdu[0]).name
        # except:
        #     pdu_name = str(self.pdu[0])
        return f'{Type(self.pdu[0]).name} {self.pdu[1]} {bytes(self.pdu[:16])}'

    def ichecksum(self, sum=0):
        """ Compute the Internet Checksum of the supplied data.  The checksum is
        initialized to zero.  Place the return value in the checksum field of a
        packet.  When the packet is received, check the checksum, by passing
        in the checksum field of the packet and the data.  If the result is zero,
        then the checksum has not detected an error.
        """
        pdu = self.pdu
        if not isinstance(pdu, (bytes, bytearray)):
            raise TypeError('Packet type should be bytes or bytearray')

        for i in range(0, len(pdu), 2):
            if i + 1 >= len(pdu):
                sum += pdu[i]
            else:
                sum += (pdu[i] << 8) + pdu[i+1]
        # take only 16 bits out of the 32 bit sum and add up the carries
        while (sum >> 16) > 0:
            sum = (sum & 0xFFFF) + (sum >> 16)
        # one's complement the result
        sum = ~sum
        return sum & 0xFFFF

    def extract(self): return self.pdu[4:]

    def corrupt(self): return self.ichecksum() != 0

    def __getattr__(self, item):
        """Get type, seq, checksum, data field from the packet
        """
        if item == 'type':
            return Type(self.pdu[0])
        elif item == 'seq':
            return Seq(self.pdu[1])
        elif item == 'checksum':
            return self.pdu[2:3]
        elif item == 'data':
            return self.pdu[4:]
        else:
            raise AttributeError


class PacketBuffer:
    """Packet buffers indexed by Seq bumber for GBNsend's send buffer or GBNrecv's receive buffer
    Note: for indexing, gbn.base attribute is used.
        popleft method updates gbn.base variable
    """
    def __init__(self, bufsize: int):
        """Packet buffer for GBNsend's send buffer or GBNrecv's receive buffer

        :param bufsize: number of pacekt cells in the buffer
        """
        self.buf = dict([(i, None) for i in range(Seq.MOD)])  # None mean empty packet
        self.base = Seq(0)
        self.bufsize = bufsize

    def __str__(self):
        l = [(Seq(seq), str(pkt)) for seq, pkt in self.buf.items() if pkt]
        l.sort()
        ll = [str(s) + ': ' + p for s, p in l]
        return '\n'.join(ll)

    def __getitem__(self, seq:Seq)-> Packet:
        self._check_key(seq)
        return self.buf[seq.seq]

    def __setitem__(self, seq:Seq, item:Packet):
        self._check_key(seq)
        self.buf[seq.seq] = item

    def __delitem__(self, seq:Seq):
        self._check_key(seq)
        self.buf[seq.seq] = None

    def _check_key(self, seq: Seq):
        if not isinstance(seq, Seq):
            raise TypeError('not Seq type')
