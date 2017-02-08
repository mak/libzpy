import libzpy.structs.zeus as zeus
import libzpy.fmt.zeus as zfmt
from libzpy.modules import template as t

from StringIO import StringIO
from ctypes import sizeof,cast,c_byte
from libzpy.libs.basecfg import BaseCfg
import json

def unpack(data,verb,verify=False):
    return t.unpack(data,verb,zeus,verify)

def parse(data,verb):
    return t.parse(data,verb,zeus)
    
def to_str(data,verb):
    if not isinstance(data,dict):
        verb('I need unpacked data')
        return

    fmt = zfmt.fmt(data)
    fmt._ = 'PowerZeus'
    return fmt.format()


def json(data):
    verb=lambda x:x
    data = unpack(data,verb,True)
    data = parse(data,verb)
    return data
        
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


def parse_basecfg(basecfg,args):

    off = args['off']
    bc = BaseCfg(basecfg)
    bc.get_rc4(off)
    return bc.get_basics()


## we allready decode basecfg
def get_basecfg(d,*args):
    return d.decode('hex')

def pack(data,verb,rand=True):
    import hashlib
    import struct as s
    hdr = zeus.Header("\x00"*sizeof(zeus.Header))
    items = []
    for idx in data:
        d = data[idx]['data']
        if not isinstance(d,basestring):
            d= s.pack('I',d)
        itm = zeus.Item("\x00"*sizeof(zeus.Item))
        itm.id = idx
        itm.flags = data[idx]['flags']
        itm.size = len(d)
        itm.realSize = len(d)
        items.append(itm.pack() + d)
    
    with open('/dev/urandom') as f: rnd=f.read(20)
    cnt = ''.join(items)
    hsh = hashlib.md5(cnt).digest()
    hdr.count = len(data.keys())
    if rand:
        hdr.rand  = (c_byte*20)(*map(ord,rnd))
        
    hdr.flags = 0
    hdr.size  = len(cnt) + sizeof(zeus.Header)
    hdr.md5 =(c_byte*16)(*map(ord,hsh))
#    ctypes.cast(f.fileName, ctypes._char_p)
    return hdr.pack() + cnt
    
    
