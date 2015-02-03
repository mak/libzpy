import structs.zeus as zeus
import fmt.zeus as zfmt
from  . import template as t

from StringIO import StringIO
from ctypes import sizeof
import json

def unpack(data,verb):
    return t.unpack(data,verb,zeus)

def parse(data,verb):
    return t.parse(data,verb,zeus)
    
def to_str(data,verb):
    if not isinstance(data,dict):
        verb('I need unpacked data')
        return

    fmt = zfmt.fmt(data)
    fmt._ = 'PowerZeus'
    return fmt.format()

        
def go(data,verb):
    data = unpack(data,verb)
    data = parse(data,verb)
    #print `data['injects']`
    print to_str(data,verb)


def format(data,verb,type='pretty'):
    if type == 'pretty':
        return to_str(data,verb)
    elif type == 'json':
        return json.dumps(data)
