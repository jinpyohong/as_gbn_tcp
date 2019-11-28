import logging, sys

# import gbn
from hong import gbn

# logging.basicConfig(level=logging.INFO, stream=sys.stderr, format='%(asctime)-15s %(message)s')
logging.basicConfig(level=logging.DEBUG, stream=sys.stderr, format='%(asctime)-15s %(message)s')

def textlines(lines):
    for i in range(lines):
        yield '%05d abcdefghijklmnopqrstuvwxyz\n' % i

gs = gbn.open(peer_host='localhost', N=16)
for line in textlines(500):
    gs.send(line.encode('utf-8'))
gs.close()
