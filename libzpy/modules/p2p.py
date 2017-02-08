"""Zeus-P2P binstorage parser """
"""
import os
import sys
import struct
import md5
import zlib

import json 

from libzpy.libs.storage import storageException

from libzpy.libs.xstream import xstream
from libzpy.libs import fmt
from libzpy.libs import cr_tools
from libzpy.libs import binPCRE

#from _local.tmp import zBinStorage
class zBinStorage(object):
  pass


#from parsers import *
#from libs.cr_tools import xorWithKey
#import libs.binPCRE
#from libs import fmt

STORAGE_HEADER_SIZE = 48 # 20 + 3*4 + 16
ITEM_HEADER_SIZE = 16 # 4*4 

FLG_ITEM_PACKED    = 0x00000001
FLG_ITEM_WEBINJECT = 0x40000000
FLG_ITEM_CONFIG    = 0x10000000 


def decode():
  pass

def _p2p_inflate(data):
  dc = zlib.decompressobj(-15)
  d = dc.decompress(data)
  return d




def unpack(data,verb,checkMD5=False,calcMD5=True,showInfo=False):
  size = len(data)
  if size < STORAGE_HEADER_SIZE + ITEM_HEADER_SIZE :
    raise storageException("Not enoungh data (<48) !")

  xs = xstream(data)
  RET = dict( head=dict() , items=[] )
  H = xs.readFmt("=20s I I I 16s ",into=('padding','size','unk1','version','md5') )
  H['padding'] = fmt.s2hex(H['padding'])
  H['md5'] =  fmt.s2hex(H['md5'])
  dif = size-H['size'] 
  if dif < 0:
    raise storageException("Data size missmatch ! (%d<->%d) " % (H['size'],size) )
  if dif > 0:
    verb( "[Warning] too much data , will truncate (lost %d bytes)" % dif  )
    xs.truncate(size - dif )

  RET['head'] = H

  if checkMD5 or calcMD5:
    tmp = xs.getPos()
    realMD5 = md5.new( xs.read() ).hexdigest()
    xs.seek(tmp)
    RET['head']['realMD5'] = realMD5

  if checkMD5:
    if RET['head']['md5'] != RET['head']['realMD5'] :
      raise storageException("Bad MD5 sum ! [ %s <-> %s ]" % (RET['head']['md5'] , RET['head']['realMD5']) )
    else:
      verb("MD5 is OK !")
  
  version = H['version']

  while  xs.availableLen() > ITEM_HEADER_SIZE :
    ih = xs.readFmt("=IIII",into=("recId","recFlag","recSize","realSize"))  
    verb(`ih`)
    key = 0xFFFFFFFF & (  ( 0x0000FFFF & ih['recId'] ) | ( ih['recSize'] << 0x10 ) | ( RET['head']['version'] << 8 ) )
    #print "KEY : %08X " % key
    binKey = struct.pack("=I",key)
    ic = xs.readN( ih['recSize'] )
    #print `ic`
    # decode item 
    ic = cr_tools.xorWithKey(ic, binKey)
    #print `ic`
    # unpack
    if ih['recFlag'] & FLG_ITEM_PACKED :
      ic = _p2p_inflate(ic)
      #print `ic`
    ih['data'] = ic
    RET['items'].append(ih)

  if showInfo:
    print RET['head']
    print "Recods : %d " % len(RET['items'])

  return RET










class format:
  def __init__(self,data,verb,to='json'):
    self.verb = verb
    for item in data['items']:
      item['data'],item['desc'] = self.processItem(item)
    if to == 'json':
      print json.dumps(data)      


  def processItem(self,i):
    F = i['recFlag']
    N = i['recId'] 
    if F & FLG_ITEM_WEBINJECT:
      return self.fmtWebinject(i)
    if F & FLG_ITEM_CONFIG:
      fn = "config_rec_%d" % N
      func = getattr(self,fn)
      return func(i)
    ## other 
    return None

  def fmtWebinject(self,i):
    data = i['data']
    xs = xstream(data)
    PARTS = []
    while xs.availableLen() > 4:
      el = xs.readFmt("=IH",into=("size","flag"))
      tmp = xs.readN( el['size'] - 6 )
      if tmp[:4] == 'ERCP':
        tmp = `binPCRE.readBinary(tmp)`
      el['data'] = tmp
      PARTS.append(tmp)
    return PARTS,"webinject"

  def config_rec_22003(self,i):
    l = fmt.NullTermStringList(i['data'])
    return l,"Webfilters"

  def config_rec_22004(self,i):
    l = fmt.NullTermStringList(i['data'])
    return l,"list2"

  def config_rec_22002(self,i):
    t = self.rec_22002(i['data'])
    return t,'webinject-table'


  def rec_22002(self,data):
    r = []
    xs = xstream( data )
    i=1
    while xs.availableLen()>4:
      wi = xs.readFmt("=IHH",into=("len","flag","id")) 
      wi['len'] -= 4 + 2 + 2 
      entry  = xstream( xs.readN(wi['len'])  )

      params=''
      for k in wi: params += ' %s=%04X|%d ' % (k,wi[k],wi[k])
     
      cond=[]
      while entry.availableLen()>4:
        cond = entry.readFmt("=III",into=("len","flag1","flag2"))
        cond['len'] -= 4*3
        cont = entry.readN( cond['len'] )
        if cont[:4] == "ERCP":
          cont = `binPCRE.readBinary(cont)`
        params = ''
        for k in cond: params += ' %s=%04X|%d ' % (k,cond[k],cond[k]) 
        cond['text'] = cont
   
      wi['conditions'] = cond
      r.append(wi)
      i+=1
    return r









class storage(zBinStorage):
  def __init__(self):
    zBinStorage.__init__(self)
    self.outbuf = ''
    

  def parseNullTermStringList(self,data):
    r = data.split(chr(0))
    for i in range(len(r)):
      self.out( "  [%d] %s \n" % (i,r[i]) )
    return r

  def readPCRE(self,data):
    txt = libs.binPCRE.readBinary(data)
    return txt 

  def rec_webinject(self,data):
    size = len(data)
    xs = xstream(data)
    PARTS=[]
    while xs.availableLen() > 4:
      
      entrySize,entryFlag = xs.readFmt("=IH")
      entrySize -= 4 + 2
    
      entryData = xs.readN(entrySize)
      self.out( "   <<--- DATA : %d | FLAG : %04X --->>\n" % ( entrySize , entryFlag ) )
      
      if entryData[:4]=='ERCP': 
        entryData = self.readPCRE(entryData)

      self.out( `entryData`+"\n" )

      self.out( "   <<--- /DATA --->>\n" )
      WI=dict(size=entrySize,flag=entryFlag,data=entryData)
      PARTS.append(WI)
    return PARTS

  def rec_22003(self,data):
    self.out( " <webfilters>\n" )
    r = self.parseNullTermStringList(data)
    self.out( " </webfilters>\n" )
    return r



  def rec_22004(self,data):
    self.out( " <xlist>\n" )
    r = self.parseNullTermStringList(data)
    self.out( " </xlist>\n" ) 
    return r
  
  def rec_22001(self,data):
    self.out(" <record 22001>\n")
    xs = xstream(data)
    #self.out(xs.hexDump())
    r=[]
    of = 0
    while xs.availableLen()>12:
      e = xs.readFmt("=IIH",into=("len","nul1","flag1") )     ;of+=10
      e['sub']=[]
      self.out("  <item size=%d nul=%08X flg1=%04X > \n" %(e['len'], e['nul1'], e['flag1']))

      toRead = e['len'] - 10;
      nRead = 0
      while nRead < toRead:
        sub = xs.readFmt("=IBBBB",into=("size","f1","f2","f3","f4"))    ;of+=8; nRead+=8;
        sub['content']=''
        if sub['size']>0:
          data = xs.readN(sub['size']-8)  ; of+=sub['size']-8; nRead+=sub['size']-8;
          cont = self.readPCRE(data)
          sub['content'] = cont
        self.out("    <element size=%d flag=[%02X,%02X,%02X,%02X]> %s</element>\n" % (sub['size'],sub['f1'],sub['f2'],sub['f3'],sub['f4'],sub['content']))
        e['sub'].append(sub)
      r.append(e)
      self.out("  </item>\n\n")
    self.out(" </record 22001>\n")
    return r  

  def rec_22002(self,data):
    self.out( " <WEBINJECT-LIST>\n" )
    r = []
    xs = xstream( data )
    i=1
    while xs.availableLen()>4:
      wi = xs.readFmt("=IHH",into=("len","flag","id")) 
      wi['len'] -= 4 + 2 + 2 
      entry  = xstream( xs.readN(wi['len'])  )

      params=''
      for k in wi: params += ' %s=%04X|%d ' % (k,wi[k],wi[k])
      self.out( "  <inject no=%d %s >\n" % ( i,params) )
     
      cond=[]
      while entry.availableLen()>4:
        cond = entry.readFmt("=III",into=("len","flag1","flag2"))
        cond['len'] -= 4*3
        cont = entry.readN( cond['len'] )
        if cont[:4] == "ERCP":
          cont = self.readPCRE(cont)
        params = ''
        for k in cond: params += ' %s=%04X|%d ' % (k,cond[k],cond[k]) 
        self.out("     <match %s> %s </match>\n" % (params,cont) )
        cond['text'] = cont
   
      self.out( "  </inject>\n")
      wi['conditions'] = cond
      r.append(wi)
      i+=1
    self.out( " <WEBINJECT-LIST>\n" ) 
    return r


  def formatRecord(self,RH,data):
    rid  = RH['recId']
    rflg = RH['recFlag']

    if rflg  & 0x40000000:
      fname = "rec_webinject"
    else :
      fname = "rec_%d" % rid

    if hasattr(self,fname):
      func = getattr(self,fname)
      fmt=func(data)
      return fmt
    else :
      self.out("< -- NOT IMPLEMENTED ID %d -- >\n" % rid )
      txt = xstream(data).hexDump() ## make nice hexdump :)
      self.out(txt)
      return txt




  def inflate(self,data,dstSize=0):
    dc = zlib.decompressobj(-15)
    d = dc.decompress(data)
    return d

  def unpack_head(self,data):

    if len(data) < 48:
      raise storageException("Need more data (1)") 

    xs = xstream(data)
    st = xs.readFmt("=20s I I I 16s ",into=('padding','size','cnt1','cnt2','md5') )
    st['padding'] = fmt.s2hex(st['padding'])
    st['md5'] =  fmt.s2hex(st['md5'])
    # convert datetime !? 

    self.out("<HEAD>\n junk\t: %s\n size\t: %d\n cnt1\t: %d\n cnt2\t: %d\n MD5\t: %s\n</HEAD>\n\n" % ( st['padding'] ,st['size'],st['cnt1'],st['cnt2'], st['md5'] ) )
 
    content = xs.read()  
    dif = len(content) - ( st['size'] - 48 ) # size of binstorage head 
    if dif <0 :
      raise storageException("Need more data (2)")
    if dif > 0:
      self.verb("Got spare bytes :%d , truncate !" % dif)
      content = content[:-dif]

    m5s = md5.new(content).hexdigest()
    st['real-md5'] = m5s 
    self.out("<content-md5> %s </content-md5>\n\n" % m5s )
    
    return st,content 


  def unpack_recs(self,st,data):
    RECS = []
    version = st['cnt2'] # filed 

    xs = xstream(data)
    while xs.availableLen()>16:     
      RH = xs.readFmt("=IIII",into=("recId","recFlag","recSize","realSize"))
      try:
        RD = xs.readN( RH['recSize'] )
      except :
        raise storageException("Fail to read record ... corupted data ?")

      self.out( "<RECORD id=%10d|%08X flag=0x%08X dataSize=%d  realSize=%d >\n" % ( RH['recId'],RH['recId'],RH['recFlag'],RH['recSize'],RH['realSize']) )

      rec_key = 0xFFFFFFFF & ( ( 0x0000FFFF & RH['recId']) | ( RH['recSize'] << 0x10 ) | ( version << 8 ) )
      rec_bin = struct.pack("I",rec_key)
      self.out( "<KEY>%08X+%08X+%08X => %08X</KEY>\n" % (RH['recId'],RH['recSize'],version,rec_key) )
      RD = cr_tools.xorWithKey(RD, rec_bin)

      if RH['recFlag'] & 0x01: ## handle zipped content 
        RD = self.inflate(RD,RH['realSize'])

      #RH['rawData']=RD
      self.dumpRecord(RD) # dump support added :)

      RH['fmtData']=self.formatRecord(RH,RD)
      self.out( "</RECORD>\n\n" )

      RECS.append(RH)
    return RECS








  def pack_rec_default(self,content):
    print " >> %s <<" % content
    return content

  def pack_nullstr(self,c):
    return ''.join( '%s\x00' % str(u) for u in c )

  def pack_rec_20003(self,c):  return self.pack_nullstr(c)
  def pack_rec_20005(self,c):  return self.pack_nullstr(c)
  def pack_rec_20009(self,c):  return self.pack_nullstr(c)
  def pack_rec_20011(self,c):  return self.pack_nullstr(c)

  def pack_rec_20007(self,c): # webi tabe
    pass

  def pack_webinject(self,c):
    xs = xstream()
    for e in c:
      l = len(e)+4
      xs.writeFmt("I",l)
      xs.write(str(e))
    return xs.dump()



  def pack_record(self,record):
    fields = ("id","content")
    for f in fields:
      if f not in record:
        raise storageException("Missing requred field: [%s]"%f)
        return

    flag = 0x0

    opts = record.get("opt",{})
    if opts.get("webinject",None):
      fn = "pack_webinject"
      flag |= 0x40000000
    else:
      fn = "pack_rec_%d" % record['id']
      if not hasattr(self,fn):
        fn = "pack_rec_default"
    
    func = getattr(self,fn)
    bindata = func(record['content'])
    size = len(bindata)
    xs = xstream()
    xs.writeFmt("=IIII",record['id'],flag,size,size)
    xs.write(bindata)
    return xs.dump()


  def pack_recs(self,recList):
    recBin = ''
    recCnt = 0
    for rec in recList:
      recBin += self.pack_record(rec)
      recCnt += 1
    size = len(recBin)
    m5s = md5.new(recBin).digest()

    xs = xstream()
    xs.write("xpad"*5)
    xs.writeFmt("=III",size,recCnt,0)
    xs.write(m5s)
    xs.write(recBin)
    xs.seek(0)
    return xs.read()
"""
