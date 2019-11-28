# TCP-like GBN protocol implementation
# with N(>=1) receive window size

import socket, select, threading, queue, time, copy, random, logging
from enum import Enum, IntEnum, auto

from packet import Seq, srange, Type, Packet, PacketBuffer

# Parameters for simulating noisy network environment
PER = 0.1               # packet error rate
LOSSRATE = 0.1          # packet loss rate
EXTRA_MEAN_DELAY = 0    # extra exponential-variate mean delay(in seconds)

# Constant definitions used in FSM
sender_port = 9977
receiver_port = 9988

class Ev(IntEnum):      # events
    Packet_Arrival  = 1
    App_Request     = 16
    TO_Retransmit   = 32
    TO_Closing      = 33
    TO_DelayedACK   = 34

# initial timeout interval
TO_interval= {
    Ev.TO_Retransmit: 0.3 + 5 * EXTRA_MEAN_DELAY,
    Ev.TO_Closing: 1,
    Ev.TO_DelayedACK: 0.5
              }


class State(Enum):   # States
    Wait    = auto()
    Closing = auto()
    Closed  = auto()


def open(peer_host, N, passive=False):
    """Open GBN protocol entity

    :param peer_host: peer host name
    :param passive: for sending (default), for receiving if True
    :return: GBN thread object
    """
    assert N < Seq.MOD, "N: too big"
    if passive:
        gbn = GBNrecv((peer_host, sender_port), N)
        gbn.start()
        logging.info('app receiver starts')
    else:
        gbn = GBNsend((peer_host, receiver_port), N)
        gbn.start()
        logging.info('app sender starts')
    return gbn


class Statistics:
    """statistics about packet exchange
    """
    def __init__(self):
        self.sent = self.dropping = self.corrupting = 0   # for packet transmission
        self.rcvd = self.corrupt = 0    # for packets reception
        self.elapsed = None

    def __str__(self):
        return f"""Packets sent: {self.sent} (dropping: {self.dropping}, corrupting: {self.corrupting})
Packets rcvd: {self.rcvd} (corrupt: {self.corrupt})
Time elapsed: {self.elapsed} sec"""


class Timer:
    """Non-threaded Timer supporting multiple timeouts
    """
    def __init__(self, intv:dict=TO_interval):
        self.times = {}
        # default timeout interval
        self.intv = intv

    def start_timer(self, key:Ev):
        self.times[key] = time.time() + self.intv[key]  # time to expire

    def stop_timer(self, key:Ev):
        if key in self.times:
            del self.times[key]

    def check_timeout(self):
        """Check if timeout occurs
        Note: invoke this method periodically

        :return: timeout event type if any
                 None, otherwise
        """
        now = time.time()
        sorted_items = sorted(self.times.items(), key=lambda x: x[1])
        for i, (key, t) in enumerate(sorted_items):
            if t <= now:
                del self.times[key]
                return key
        else:
            return None

    def set_intv(self, key:Ev, intv):
        """Set new timeout interval"""
        if key in self.intv:
            self.intv[key] = intv
        else:
            raise KeyError

    def get_intv(self, key:Ev):
        """Get current timeout inverval"""
        return self.intv[key]


# GBN abstract super class running in a thread
class GBN(threading.Thread):
    def __init__(self, peer):
        """
        :param N: (send or receive) buffer size
        """

        threading.Thread.__init__(self, name=self.__class__.__name__)

        # connected UDP socket. Actually, no 3-way handshake like TCP
        # just for omitting `to` field and for easy handing socket error
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if peer[1] == sender_port:
            self.sock.bind(('', receiver_port)) # receiver socket addr
        else:
            self.sock.bind(('', sender_port))   # sender socket addr
        self.sock.connect(peer)     # just for remembering peer address

        self.down_queue = queue.Queue(1)    # interface from app to GBN
        self.up_queue = queue.Queue(1)      # interface from GBN to app
        self.stats = Statistics()
        self.timer = Timer()

    # lower layer(UDT) interface complying with the textbook
    def udt_send(self, packet: Packet):
        """Unreliable data transfer via connected UDP socket
        to simulate noisy, lossy, and random delayed network environment
        """
        # enforce loss
        self.stats.sent += 1
        if LOSSRATE > 0 and random.random() <= LOSSRATE:
            self.stats.dropping += 1
            logging.info(f'udt_send: [dropping] {packet}')
            return
        # enforce delay
        if EXTRA_MEAN_DELAY > 0:
            # send after exponential distributed delay
            time.sleep(random.expovariate(1.0 / EXTRA_MEAN_DELAY))
        # enforce bit error
        if PER >0 and random.random() < PER:
            pdu = copy.copy(packet.pdu)  # deep copy for emulating bit errors
            i = random.randrange(len(pdu))
            pdu[i] = pdu[i] ^ 1  # XOR, enforce bit error
            self.sock.send(pdu)
            self.stats.corrupting += 1
            logging.info(f'udt_send: [corrupting] {Packet(pdu)}')
        else:
            self.sock.send(packet.pdu)
            logging.debug(f'udt_send: {packet}')

    def rdt_rcv(self):
        """Unreliable data reception via connected UDP socket
        """
        pdu = self.sock.recv(2048)  # remove the packet
        packet = Packet(pdu)
        # logging.debug(f'rdt_rcv:  {packet}')
        self.stats.rcvd += 1
        if packet.corrupt():
            self.stats.corrupt += 1
        return packet

    # API - called by sending applications
    def send(self, data):
        """Request to send data
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError('Data should be bytes or bytearray type')
        if data:
            self.down_queue.put(data)
            logging.debug(f'send: {data}')

    def close(self):
        """Request to close the session
        """
        self.down_queue.put(b'')    # empty byte denotes end of data
        while True:
            if self.down_queue.empty():
                logging.info('app terminates')
                return
            time.sleep(0.001)

    # API - called bu receiving applications
    def recv(self):
        """Request to receive data

        :return: data (bytes or bytearray type)
        """
        return self.up_queue.get()

    # Methods implementing the functions defined in the textbook
    # used in this protocol
    def deliver(self, data):
        self.up_queue.put(data)
        logging.debug(f'deliver: {data}')

    # Wrapper methods
    def check_event(self, down_queue=None):
        # Check packet arrival
        readable, writable, exceptional = select.select([self.sock], [], [self.sock], 0.)
        if self.sock in exceptional:
            raise OSError('socket error')
        if self.sock in readable:  # something arrives?
            return Ev.Packet_Arrival
        # Check timeout
        event = self.timer.check_timeout()
        if event:
            return event
        # Check data arrival from the application
        if down_queue is None:
            return None
        if down_queue.empty():
            return None
        else:
            return Ev.App_Request

    # delegate implementation to subclasses for providing same interface
    def _log(self, event='', chunk=''):
        raise NotImplementedError

    def get_event(self):
        raise NotImplementedError

    def fsm(self):
        raise NotImplementedError

    #  thread.start() calls this method
    def run(self):
        logging.info(f'{self.__class__.__name__} starts')
        try:
            self.fsm()
        except:
            import sys
            logging.exception(sys.exc_info()[:2])
        else:
            logging.info(f'{self.__class__.__name__} terminates')
            print('*** GBN parameters ***')
            print('Window size:', self.N)
            print('LOSSRATE:', LOSSRATE, 'PER:', PER, 'extra MEAN_DELAY:', EXTRA_MEAN_DELAY)
            print('\n*** Statistics ***')
            print(self.stats)
            print("hong.gbn")


# GBN Sending-side Protocol Entity
class GBNsend(GBN):
    def __init__(self, peer, N):
        """GBN sending-side

        :param peer: peer (hostname, port)
        :param N:    send window size
        """

        GBN.__init__(self, peer)
        self.N = N     # buffer size
        self.sndbuf = PacketBuffer(self.N)
        self.state = State.Wait
        self.base = Seq(0)
        self.next_seq = Seq(0)

    # Wrapper methods used in FSM
    def retransmit(self):
        """Retransmit all the packets in the send buffer"""

        ### Your code here
        pass

    def send_packet(self, type, data=b''):
        """Make new packet and send it

        :param type: packet type
        :param data: payload
        """

        ### Your code here
        pass

    def handle_ACK(self, packet):
        """Handle arriving ACK packet
        """

        ### Your code here
        pass

    def get_event(self):
        while True:
            event = self.check_event(self.down_queue)
            # if send buffer is full, postpone Ev.App_Request
            if event == Ev.App_Request and not (self.next_seq < (self.base + self.N)):
                event = None
            if event:
                return event
            time.sleep(0.01)

    def _log(self, event='', chunk=''):
        event_name = event.name if event else ''
        if event == Ev.Packet_Arrival and chunk.corrupt():
            chunk = '*corrupt*'
        logging.info(f'{self.state.name} {self.base}:{self.next_seq} {event_name} {chunk}')

    # GBN sending-side FSM
    def fsm(self):
        while self.state != State.Closed:
            event = self.get_event()
            if event == Ev.Packet_Arrival:
                rcvpkt = self.rdt_rcv()
                self._log(event, rcvpkt)
            elif event == Ev.TO_Retransmit:
                self._log(event)
            elif event == Ev.App_Request:
                data = self.down_queue.get()
                self._log(event, data)
            else:
                self.error('Unknown event: %d' % event)
                continue

            # state transition
            if self.state == State.Wait:
                ### Your code here
                pass

                continue

            if self.state == State.Closing:     # FIN sent, then waiting for FINACK
                if event == Ev.TO_Retransmit:  # not yet ACKnowleged for DATA or FIN sent
                    self.retransmit()
                elif event == Ev.Packet_Arrival:
                    if not rcvpkt.corrupt() and rcvpkt.type & Type.ACK:
                        self.handle_ACK(rcvpkt)      # remaining ACKs
                        if self.base == self.next_seq:  # no more packets to retransmit
                            self.state = State.Closed
                    else:
                        pass        # do nothing if packet corrupted, etc.
                continue
        # end of while loop

        # Closed state
        self._log()
        time.sleep(2)  # to avoid ConnectionResetError in Windows


# GBN Receiving-side Protocol Entity
class GBNrecv(GBN):
    def __init__(self, peer, N):
        """GBN receiving-side

        :param peer: peer (hostname, port)
        :param N:    receive window size
        """

        GBN.__init__(self, peer)
        self.N = N     # buffer size
        self.rcvbuf = PacketBuffer(self.N)
        self.state = State.Wait
        self.base = Seq(0)
        self.FIN_delivered = False

    def get_event(self):
        while True:
            event = self.check_event()
            if event:
                return event
            time.sleep(0.01)

    def _log(self, event='', chunk=''):
        event_name = event.name if event else ''
        if event == Ev.Packet_Arrival and chunk.corrupt():
            chunk = '*corrupt*'
        logging.info(f'{self.state.name} {self.base}:{self.base+self.N} {event_name} {chunk}')

    def feedback_ACK(self):
        """Make an ACK packet then send it
        """

        ### Your code here
        pass

    def handle_packet(self, rcvpkt):
        """Handle received packet of type DATA or FIN

        Save it into buffer, and scan the rcvbuf.
        Deliver in-order data to the receiver app.
        When FIN data(b'') has delivered, mark to notify it to FSM as follow:
            self.FIN_delivered = True
        """

        ### Your code here
        pass

    def fsm(self):
        start_time = None

        while self.state != State.Closed:
            event = self.get_event()
            if event == Ev.Packet_Arrival:
                rcvpkt = self.rdt_rcv()
                self._log(event, rcvpkt)
            elif event >= Ev.TO_Retransmit: # all timeout events
                self._log(event)
            else:
                logging.error('Unknown event: %d' % event)
                continue

            if start_time is None:
                start_time = time.time()

            # state transition
            if self.state == State.Wait:
                ### Your code here
                pass

                continue

            # Whenever GBNsend do not receive the final ACK,
            # duplicated FIN might be coming.
            if self.state == State.Closing:
                if event == Ev.TO_Closing:         # termination timer timeout
                    self.state = State.Closed
                elif event == Ev.Packet_Arrival:
                    self.feedback_ACK()  # retransmit
                continue
        # end of while loop

        # Closed state
        self.stats.elapsed = time.time() - start_time
        self._log()


