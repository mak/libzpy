import libzpy.structs.vmzeus20 as k
import libzpy.fmt.vmzeus20 as pzfmt
from libzpy.modules import template as t


from ctypes import sizeof
import json,struct


def _print(data,ver):
    import pprint
    pprint.pprint(data)

def unpack(data,verb):
    return t.unpack(data,verb,k)
def parse(data,verb):
    return t.parse(data,verb,k)

def to_str(data,verb):
    if not isinstance(data,dict):
        verb('I need unpacked data')
        return

    fmt = pzfmt.fmt(data)
    fmt._name = 'VMZeus-2.0'
    return fmt.format()


def json(data):
    verb=lambda x:x
    data = unpack(data,verb)
    data = parse(data,verb)
    if 'CFGID_SIGNATURE' in data:
        data['CFGID_SIGNATURE'] =data['CFGID_SIGNATURE'].encode('hex')
    data['CFGID_CONFIG_CREATION_TIME'] = struct.unpack('I',data['CFGID_CONFIG_CREATION_TIME'])[0]
    
    return data

def go(data,verb):
    data = unpack(data,verb)
    data = parse(data,verb)
    #print `data['injects']`
    print to_str(data,verb)
