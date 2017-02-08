import libzpy.structs.vmzeus2 as k
import libzpy.fmt.vmzeus2 as pzfmt
from libzpy.modules import template as t


from ctypes import sizeof
import json
from struct import *

def _print(data,ver):
    import pprint
    pprint.pprint(data)

def do_print(data,verb):
    print data


def unpack(data,verb):
    return t.unpack(data,verb,k)
def parse(data,verb):
    return t.parse(data,verb,k)

def json(data):
    verb=lambda x:x
    data = unpack(data,verb)
    data = parse(data,verb)
    return data

def to_str(data,verb):
    if not isinstance(data,dict):
        verb('I need unpacked data')
        return

    fmt = pzfmt.fmt(data)
    fmt._name = 'VMZeus-2.0'
    return fmt.format()

def go(data,verb):
    data = unpack(data,verb)
    data = parse(data,verb)
    #print `data['injects']`
    print to_str(data,verb)
