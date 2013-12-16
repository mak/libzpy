import StringIO
import struct
import string
import os


def glue(parts,delim='',preproc=None):
  if preproc:
    for fn in preproc:
      parts = map( fn , parts )
  return delim.join(parts)

class streamError(Exception):
  msg=None
  def __init__(self,m=None):
    self.msg=m
  def __str__(self):
    if self.msg:
      return "Error: "+self.msg
    else: 
      return "Error: unknow error "

def unpackEx(fmt,data,into=None):
  #print "Will unpackt [%s] [%s]" % (fmt,`data`)
  t = struct.unpack(fmt,data)
  if not t :
    return None
  if not into:
    return t
  if len(t) != len(into):
    raise streamError("readFmt into values : size mismatch [%d != %d]" % (len(into),len(t)))
  return dict( (into[i],t[i]) for i in range(len(into))  )  

class xstream(StringIO.StringIO):
  
  def readN(self,n):
    d = self.read(n)
    if len(d) < n:
      raise streamError("Read error : need %d bytes, got %d " % ( n , len(d) ))
    return d
   
  def readFmt(self,fmt,into=None):
    n = struct.calcsize(fmt)
    d = self.readN(n)
    return unpackEx(fmt,d,into)

    # old code :
    t = struct.unpack(fmt,d)
    if not t:
      return None
    if not into:
      return t
    if len(into) != len(t):
      raise streamError("readFmt into values : size mismatch [%d != %d]" % (len(into),len(t)))
    D={}
    for i in range(len(into)):
      D[into[i]] = t[i]
    return D


  def readOne(self,fmt):
    d = self.readFmt(fmt)
    return None if d is None else d[0]
  
  def readAll(self):
    s = self.getLen()
    p = self.getPos()
    d = s - p
    return self.readN(d)
 

  def append(self,data):
    p = self.tell()
    self.seek(0, os.SEEK_END)
    self.write( data )
    self.seek(p)

  def appendFmt(self,fmt,*a):
    return self.append(struct.pack(fmt, *a) )

  def writeFmt(self,fmt,*a):
    return self.write( struct.pack(fmt , *a) )
  
  def writePascalData(self,data,fmt="!H"): # lol :D
    self.writeFmt(fmt,len(data))
    self.write(data)

  def readme(self):
    p = self.tell()
    self.seek(0)
    v = self.read()
    self.seep(p)
    return v

  def dump(self):
    return self.getvalue()

  def getLen(self):  
    org = self.tell()
    self.seek(0, os.SEEK_END)
    end = self.tell()
    self.seek(org)
    return end

  def getPos(self):
    return self.tell()
  
  def availableLen(self):
    return self.getLen() - self.getPos()

  def printStatus(self):
    print " Len: %d Pos: %d " % ( self.getLen() , self.getPos() )

  def hexDump(self,inRow=16,title=None,head=True):
    S = ' \n'
    if head:
      if title:
        S += " .----[ %s ]----- \n" % title
      S += "| offset          ascii                 hex   \n"
    p = self.tell() # save 
    self.seek(0)    # rewind
    fmt = "| 0x%08X %-"+str(inRow)+"s \t %s\n"
    while True:
      of = self.tell()
      chunk = self.read(inRow)
      hx = ''
      ch = ''
      for c in list(chunk):
        ch+= c if ord(c)>=32 and ord(c)<127 else '.'
        hx += "%02X " % ord(c)
      S += fmt % (of,ch,hx)
      if len(chunk) < inRow:
        break
    S+= "| 0x%08X \n" % self.tell()
    S+= "`-- \n"
    self.seek(p)
    return S

  
  





