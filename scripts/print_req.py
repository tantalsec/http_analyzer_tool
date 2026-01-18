from pprint import pprint
import msgpack
import sys

with open(sys.argv[1], "rb") as f:
    s = f.read()
    pprint(msgpack.unpackb(s, raw=True))
