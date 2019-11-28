import logging, sys

# import gbn
from hong import gbn

# logging.basicConfig(level=logging.INFO, stream=sys.stderr, format='%(asctime)-15s %(message)s')
logging.basicConfig(level=logging.DEBUG, stream=sys.stderr, format='%(asctime)-15s %(message)s')

gr = gbn.open(peer_host='localhost', N=16, passive=True)
while True:
    data = gr.recv()
    if data == b'':
        break
    print(data.decode('utf-8'), end='')
