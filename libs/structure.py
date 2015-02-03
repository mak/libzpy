from ctypes import *
#try: 
#    from cStringIO import StringIO
#except ImportError:
from StringIO import StringIO
from libs.kdNRV2b import inflate as unrv2b

c_word  = c_uint16
c_dword = c_uint32
c_qword = c_uint64

## i need 32bit wchar...
c_wchar = c_wchar if sizeof(c_wchar) == 2 else (2*c_char)

class DataStructure(Structure):
    _flags = {} 
    _have_data = True
    _sep = ' '

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
            #print bytes.tell()
            #print self._fields_
            #print sizeof(self)
            data  = bytes.read(sizeof(self))

        memmove(addressof(self), c_char_p(data), sizeof(self))
        if self._have_data:
            self.read(bytes)

    def _str_field(self,args):
        if type(args) == str:
            args = (args,0)
        n,t = args
        if hasattr(self,'_print_%s' % n):
            return (n,getattr(self,'_print_%s' % n)())
        elif t == c_word:
            return (n,'0x%04x' % getattr(self,n))
        elif t == c_dword:
            return (n,'0x%08x' % getattr(self,n))
        elif getattr(self,n).__class__ == str:
            return (n,getattr(self,n).encode('string_escape'))

    def _p_field(self,a):
        return str(self._str_field(a))
#        return #'%s: %s' % (a,self._str_field(a))

    def _print_flags(self):
        ret = []
        for fl in self._flags:
            if self.flags & self._flags[fl]:
                ret.append(fl)
        try:
            return ' | '.join(ret)  + "\n"
        except:
            return ''

    def __str__(self):
        return self._sep.join(map(self._p_field,self._fields_))

    def json(self):
         import json
         return json.dumps(dict(map(self._str_field,self._fields_)))
        

class StructList(object):
    struct = None

    def __init__(self,data):
        self.data = data.data if isinstance(data,DataStructure) else data
        self.size = data.realSize if isinstance(data,DataStructure) else len(data)
        self.off = 0

    def  __iter__(self):
        return self

    def next(self):
        if self.off >= self.size:
            raise StopIteration
        ib = self.struct(self.data[self.off:])
        self.off += ib.size
        return ib
