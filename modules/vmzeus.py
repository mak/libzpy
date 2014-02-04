import structs.kins as k
import fmt.powerzeus as pzfmt
from . import template as t


from ctypes import sizeof
import json
from struct import *

def unpack(data,verb):
    return t.unpack(data,verb,k)
def parse(data,verb):
    return t.parse(data,verb,k)

def to_str(data,verb):
    if not isinstance(data,dict):
        verb('I need unpacked data')
        return

    fmt = pzfmt.fmt(data)
    fmt._name = 'VMZeus'
    return fmt.format()

def go(data,verb):
    data = unpack(data,verb)
    data = parse(data,verb)
    #print `data['injects']`
    print to_str(data,verb)
