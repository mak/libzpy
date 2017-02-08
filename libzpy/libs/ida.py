import idc


class ifile(object):
    def __init__(self,addr,use_debugger=False):
        self.off  = 0
        self.addr = addr
        self.dbg  = use_debugger

    def byte(self,a=None):
        if not a:
            a  = sefl.addr + self.off
        self.off += 1
        return DbgByte(a) if self.dbg else Byte(a)

    
    def word(self,a=None):
        if not a:
            a  = sefl.addr + self.off
        self.off += 2
        return DbgWord(a) if self.dbg else Word(a)

    
    def dword(self,a=None):
        if not a:
            a  = sefl.addr + self.off
        self.off +=4
        return DbgDword(a) if self.dbg else Dword(a)
    
    def bytes(self,n,a=None):
        return map(ord,self.bytes(n,a))
    
    def read(self,n,a=None):
        if not a:
            a  = sefl.addr + self.off
        self.off += n
        return ReadManyBytes(a,n,self.dbg)
