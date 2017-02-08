import re
from struct import unpack

import libzpy.libs.cr_tools as cry


class BaseCfg(object):

    def __init__(self,cfg):
        self.cfg = cfg
        self.rc4sbox = None

    def get_strings(self):
        ss =map(lambda x: x.strip("\x00"),re.findall("[\x1f-\x7e]{6,}\x00", self.cfg))
        if self.urls:
            return list(set(ss).difference(set(self.urls)))
        return  ss

    def get_botname(self):
        _max = lambda x : max(x,key=len) if x else ''
        return _max(filter(lambda x: x and not "\x00" in x,map(lambda x:x[0].decode('utf-16'),re.findall("((.\x00)+)\x00\x00",self.cfg))))


    def get_urls(self):
        self.urls = map(lambda x:x.strip("\x00"),re.findall("https?://[\x1f-\x7e]{6,}\x00",self.cfg))
        return self.urls

    def rc4(self,d,k):
        return cry.rc4decrypt(d,k)

    def get_rc4(self,pes):

        if type(pes) == int:
            ## some time im off few byts, lets try to fix this
            rb = self.cfg[pes:pes+0x102]
            off1= pes - ( 0x102 - rb.rfind("\x00\x00") -2)
            self.rc4sbox = self.cfg[off1:off1+0x102]
            return self.rc4sbox
            

        mg = len(pes)

        for idx in xrange(len(self.cfg)-0x100):
            try:
                ss = unpack('I',self.rc4(pes,self.cfg[idx:idx+0x102])[0:4])[0]

                if ss == mg:
                    print '[+] found rc4key'
                    self.rc4sbox = self.cfg[idx:idx+0x102]
                    return self.rc4sbox

            except Exception as e:
                print `e`
                pass

    def get_basics(self):
        if not self.rc4sbox:
            raise Exception('parse your shit bro')

        st = {}
        st['botname']=self.get_botname()
        st['rc4sbox']=self.rc4sbox.encode('hex')
        st['urls'] = self.get_urls()
        st['strings'] = self.get_strings()
        if st['urls']:
            st['cfg'] = st['urls'][0]
        else:
            st['cfg'] = ''
        return st
    

                   
