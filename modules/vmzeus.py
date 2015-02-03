import sys,StringIO,re
import structs.kins as k
import fmt.powerzeus as pzfmt
#import libs.cr_tools as cry
from . import template as t
from libs.vmzeus import VmContext as VM
from libs.basecfg import BaseCfg
from ctypes import sizeof
from struct import *
from hashlib import md5
from pprint import pprint


class VMZCfg(BaseCfg):
    def _get_enc_urls(self,k=None):
        d = self.cfg
        k = k if k else self.rc4sbox
        rk = k[:-2][::-1]
        off = d.find(k)
        if off == -1:
            print 'No key... wrong baseconfig/key?'
            return
        i = 0
        ret =[];els = []
        while i < len(d):
            if i == off:
                i+= 0x102
            else:
                dec = self.rc4(d[i:i+0x66],rk)
                if dec.find('http') != -1:
                    ret.append(dec.split("\x00")[0])
                elif re.search("[\x1f-\x7e]{6,}\x00",dec):
                    els.append( re.search("([\x1f-\x7e]{6,})\x00",dec).group(1) )
                i+=1
        self.urls = ret
        return ret,els

    def get_urls(self):
        if not self.urls:
            self._get_enc_urls()
        return self.urls

    def get_rc4(self,ks):
        ## brutforece to find botnet rc4 key try to find baseurl 
        ## if succeded its our key - should work well
        if type(ks) != list:
            self.rc4sbox = ks.decode('hex')
            return self.rc4sbox

        r = None
        for k in ks:
            try:
                temp = self._get_enc_urls(k)
                if temp and temp != ([],[]) and any(map(lambda u: u.startswith('http'),temp[0])):
                    r = k
            except Exception as e:
                # import traceback
                # print `e`
                # traceback.print_exc(file=sys.stdout)
                pass
        self.rc4sbox = r
        return r
    

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

def do_print(data,verb):
    print data

def json(data):
    return go(data,lambda x:x)

def go(data,verb):
    data = unpack(data,verb)
    data = parse(data,verb)
    #print `data['injects']`
    return data


def vmzeus_dga(key,suff,idx=0):
    key = key[::-1][2:]
    key = chr(ord(key[0]) + idx) + key[1:] + "\x00\x00"
    return 'http://' + md5(key).hexdigest()[:11] + suff

def parse_basecfg(basecfg,data):
#   print `basecfg`
   key = data['key']
   rc6k = data.get('off',None)

   bc = VMZCfg(basecfg)
   bc.get_rc4(key)
   staticcfg = bc.get_basics()
   fakeurl = re.search('(http://[a-zA-Z0-9/.]*\x00)',bc.cfg).group(1)
   if rc6k:
       staticcfg['rc6sbox']= basecfg[rc6k:rc6k+0xb0].encode('hex')
   for u in filter(lambda x: x.endswith('.jpg'),bc.urls):
       staticcfg['cfg'] =u

   staticcfg['urls']
   staticcfg['fakeurl'] =  (fakeurl if fakeurl else '*UNKNOWN*').strip("\x00")
#   staticcfg['OtherEncStrings'] = `els`
#   staticcfg['OtherStrings']= `othr`
   return staticcfg

#   print 'DGA: ' + `[ vmzeus_dga(key,els[0],i) for i in range(0,5)]`
   

def get_basecfg(data,verb,*args):
   oldstdout = sys.stdout
   #fd = open('/tmp/out','w')
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
#   print `cfg`
   return cfg

# def decrypt_cfg(data,key):
#    print 'Data: ' + `data`
#    print 'Key: ' + `key`
#    data = cry.rc4decrypt(data,key)
#    return cry.visDecry(data)


