import json
import sys,StringIO,re
import structs.kins as k
import fmt.powerzeus as pzfmt
from . import template as t
from libs.vmzeus import VmContext as VM
from libs.basecfg import BaseCfg
from ctypes import sizeof
from struct import *
from hashlib import md5
from pprint import pprint


class KinsCfg(BaseCfg):
    def get_rc4(self):
        self.rc4sbox = 'placeholder'
    
    def get_aes(self,off):
        self.get_rc4()
        self.aes = self.cfg[off:off+16]
        return self.aes

    def get_ua(self):
        self.ua = re.search("(Moz[^\x00]+)\x00",self.cfg).group(1)
        return self.ua

    def get_basics(self):
        st = super(KinsCfg,self).get_basics()
        del st['rc4sbox']
        st['aes-key']= self.aes.encode('hex')
        st['user-agent']=self.get_ua()
        return st

    
    
def unpack(data,verb):
    return t.unpack(data,verb,k)
def parse(data,verb):
    return t.parse(data,verb,k)

def to_str(data,verb):
    if not isinstance(data,dict):
        verb('I need unpacked data')
        return

    fmt = pzfmt.fmt(data)
    fmt._name = 'KiNS'
    return fmt.format()

def go(data,verb):
    data = unpack(data,verb)
    data = parse(data,verb)
    #print `data['injects']`
    r = to_str(data,verb)
    #print r
    return r


def get_basecfg(data,verb,*args):
   oldstdout = sys.stdout
   #fd = open('/tmp/out','w')
#   print 'Code hash: ' + md5(data['code'].decode('hex')).hexdigest()
#   print 'Data hash: ' + md5(data['data'].decode('hex')).hexdigest()
   sys.stdout = StringIO.StringIO()
   cfg = None
   try:
     vmctx = VM(data['code'].decode('hex'),data['data'].decode('hex'))
     vmctx._fix_xors(data['magic'])
     vmctx.run()
     cfg = vmctx.config

   except Exception as e:
	import traceback
   	sys.stdout = oldstdout 
	print 'VMError: ' + `e` 
	traceback.print_exc(file=sys.stdout)

   sys.stdout = oldstdout 
#   fd.close()
   if not cfg:
      print 'Code hash: ' + md5(data['code'].decode('hex')).hexdigest()
      print 'Data hash: ' + md5(data['data'].decode('hex')).hexdigest()
      print 'Xors: ' + str(data['magic'])
   return cfg





def parse_basecfg(basecfg,_args): #key,off,verb):

#   print `basecfg`
   off=_args['off']
   cfg  = KinsCfg(basecfg)
   cfg.get_aes(off)
   return cfg.get_basics()
