import StringIO
import struct
import string
import os
import numpy
import sys


class nrv2bError(Exception):
  pass

def wr(s):
  print s
  return
  sys.stdout.write(s)


class inflate:
  def __init__(self,data,outSize):
    self.bb = 0
    self.bc = 0
    self.olen = 0
    self.ilen = 0
    self.src = map(ord,list(data))
    self.dst = list(  0 for i in range(outSize)  )
    self.imax = len(data)
    self.omax = outSize

  def readDWORD(self):
    val = 0
    pos = self.ilen 
    d = ''.join(map(chr,self.src[pos:pos+4]))
    val = struct.unpack('<I',d)[0]
    #print " <<>> read dw : "+hex(val)
    return val

  def getBit(self): # get next bit from buff or read new data into buff
    if self.bc:
      self.bc -= 1
    else: # read bc 
      self.bc = 31
      self.bb = self.readDWORD()
      self.xilen(4) 

      # show my bits 
      s1=""; s2=""
      for i in range(32):
        s1+="%2d " %i; s2+=" %d " % ( (self.bb >> i ) & 1 )
    #  print s1; print s2

    #wr("(bit[%2d]=%2d) " % ( self.bc, (self.bb >> self.bc ) & 0x01 ) )
    return ( self.bb >> self.bc ) & 0x01
  

  def xolen(self,n=1):
    if self.olen >= self.omax:
      raise nrv2bError("OUT-OVERRUN")
    self.olen+=n
    return self.olen
 
  def xilen(self,n=1):
    if self.ilen >= self.omax:
      raise nrv2bError("IN-OVERRUN")
    self.ilen += n
    return self.ilen

  def push(self,c):
    self.dst[self.olen]=c
    #wr("(PUSH %s)" % `chr(c)` )
    self.xolen(1)

  def pop(self):
    c = self.src[self.ilen]
    #wr("(POP  %s)" % `chr(c)` )
    self.xilen()
    return c


  def run(self,output=0):
    m_off = 0
    m_len = 0
    last_m_off = 0

    while True:

      while self.getBit():      
        self.push( self.pop()  )
      
      m_off = 1
      
      while True:
        m_off = m_off * 2 + self.getBit()
        if m_off > 0xffffff + 3:
          raise nrv2bError("LOOKBEHIND-1 [ %d > 0xffffff] " % m_off )
        if self.getBit():
          break

      if m_off == 2:
        m_off = last_m_off 
      else:
        m_off = (m_off-3)*256 + self.pop()
        if m_off == 0xffffffff:
          break
        m_off +=1 
        last_m_off = m_off 

      m_len = self.getBit()
      m_len = m_len*2 + self.getBit()

      if m_len == 0:
        m_len +=1 
        while True:
          m_len = m_len*2 + self.getBit()
          if m_len > self.omax:
            raise nrv2bError("OUTPUT-1 [%d >%d]" % (m_len,self.omax) )
          if self.getBit():
            break
        m_len += 2

      m_len += (m_off > 0xD00)
      if self.olen + m_len > self.omax:
        raise nrv2bError("OUTPUT-2 [%d + %d >  %d ]" % ( self.olen , m_len, self.omax ) )
      if m_off > self.olen:
        raise nrv2bError("LOOKBEHIND-2 [ %d > %d ]"%(m_off,self.olen))
     
      m_pos = self.olen - m_off 
      
      self.push( self.dst[ m_pos ] )
      m_pos += 1

      while m_len>0:
        self.push( self.dst[m_pos]  )
        m_pos +=1 
        m_len -=1 

    if output:
      return self.getOutput() 

  def getOutput(self):
    return ''.join(map(chr,self.dst))

