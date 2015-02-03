
import structs.zeus as zeus
import fmt.zeus as zfmt
from  . import template as t

from StringIO import StringIO
from ctypes import sizeof
from libs.basecfg import BaseCfg
import json


class mmbbCfb(BaseCfg):
    
    def get_rc4(self,off):
        #(4,10,0)
        o=self.cfg.find('\x04\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x00')
        self.aesKey = self.cfg[o+4+off:o+4+off+0x10]
        self.rc4sbox = self.cfg[o:]
        return self.rc4sbox

    def get_basics(self):
        st=super(mmbbCfb,self).get_basics()
        st['aes-key'] = self.aesKey.encode('hex')
        return st

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

    off = args['aoff']#
    bc = mmbbCfb(basecfg)
    bc.get_rc4(off)
    return bc.get_basics()


## we allready decode basecfg
def get_basecfg(d,*args):
#    print d
    return d.decode('hex')
