from ctypes import *
#try: 
#    from cStringIO import StringIO
#except ImportError:
from StringIO import StringIO
from libs.kdNRV2b import inflate as unrv2b

c_word  = c_uint16
c_dword = c_uint32
c_qword = c_uint64


class DataStructure(Structure):
    _flags = {} 
    _have_data = True

    def __init__(self,data):
        super(DataStructure,self).__init__()
        self.feed(data)
    
    def read(self,data):
        if isinstance(data,StringIO):
            self.data = data.read(self.size)
        else: 
            self.data = data[sizeof(self):self.size]
    
    def feed(self, bytes):
        data = bytes
        if isinstance(data,StringIO):
            data  = bytes.read(sizeof(self))

        memmove(addressof(self), c_char_p(data), sizeof(self))
        if self._have_data:
            self.read(bytes)

    def _str_field(self,args):
        n,t = args
        if hasattr(self,'_print_%s' % n):
            return getattr(self,'_print_%s' % n)()
        elif t == c_word:
            return '%s: 0x%04x' % (n,getattr(self,n))
        elif t == c_dword:
            return '%s: 0x%08x' % (n,getattr(self,n))

    def _print_flags(self):
        ret = []
        for fl in self._flags:
            if self.flags & self._flags[fl]:
                ret.append(fl)
        try:
            return 'FLAGS: ' + ' | '.join(ret) + "\n"
        except:
            return 'FLAGS: '

    def __str__(self):
        return ' '.join(map(self._str_field,self._fields_))
