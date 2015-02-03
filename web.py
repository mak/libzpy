from bottle import route, run,post,request,static_file
from hashlib import md5
import pymongo
import os,json,socket
import libzpy

def print_cfg(cfg,type,parser):
   return
   CFG=parser.go(cfg,lambda x:x)
   if CFG:
      CFG = parser.to_str(CFG,lambda x:x)
      print '[*] CFG END'
      cfg_date =datetime.datetime.now().strftime('%s')
      with open('/tmp/%s.%s.cfg'%(type,cfg_date),'w') as f: f.write(CFG)
      print '[*] Config saved in /tmp/%s.%s.cfg'%(type,cfg_date)
      return 'OK' 
   return None


DATABASE='mongodb://malwaredb.cert.pl:27017/'
def get_db():
       return pymongo.MongoClient(DATABASE)
    

def remember(json):

    def get_data_hash(d):
        import json
        try:
            del d['OtherEncStrings']
            del d['OtherStrings']
        except:
            pass

        del d['timestamp']
        return md5(json.dumps(d)).hexdigest()


    kt = None
    if 'rc6sbox' in json:
        kt = 'rc6sbox'
    elif 'aes-key' in json:
        kt = 'aes-key'
    elif 'rc4sbox' in json:
        kt = 'rc4sbox'
    elif 'aessbox' in json:
        kt = 'aessbox'
    elif 'rc4key' in json:
        kt='rc4key'
    

    if kt:
        json['cfg-key'] = kt
        json['timestamp'] = datetime.now()
        json['datahash'] = get_data_hash(json.copy())
        json['alive']=True
        json['cnc']  = urlparse(json['cfg']).netloc
        c =  get_db()
        try:
            
            c.zeus.config.insert(json)
        except pymongo.errors.DuplicateKeyError:
            pass
        c.close()

    

@route('/prr/cfg',method='POST')
def handle_cfg():
   data = request.json
   mod = libzpy.get_parser(data['type'].lower())
   del data['type']
            

@route('/ppr/basecfg',method='POST')
def handle_basecfg():
   data = request.json
   mod = libzpy.get_parser(data['type'].lower())
   del data['type']

   basecfg= None
   key =None
   md5 = None
   version = None
   _data = {}

   if 'binary' in data:
      print 'Sample: ' + data['binary']
      md5 = data['binary']
      del data['binary']
      
   if 'version' in data:
      v = data['version']
      version = "%02d.%02d.%02d.%02d"%(v>>24,(v>>16)&0xff,(v>>8)&0xff,v&0xff)
      print '[+] Version: %s' % version
      del data['version']

   if 'BaseConfig' in data:
      basecfg=parser.get_basecfg(data['BaseConfig'],data.get('key',''),lambda x:x)
      key = []
      for h in re.finditer("\x00\x00",basecfg):
         key.append(basecfg[h.start()-0x100:h.start()+2])
      del data['BaseConfig']
      _data['key'] = filter(None,key)
                  
      key = True

   if 'login_key' in data:
      _data['lk'] = data['login_key'].strip("\x00")

   if 'salt' in data:
      _data['s'] = data['salt']

   if 'aes_xor' in data:
      _data['aes_xor'] = data['aes_xor']

   if 'pesettings' in data:
      key = data['pesettings']['key'] 
      pesets = conf.pesettings(data['pesettings']['data'].decode('hex'),lambda x:x,type)  
      del data['pesettings']

   if 'mutex' in data:
      if not key:
         key = data['mutex']['key']
      print 'Mutex: ' + data['mutex']['data']
      del data['mutex']
   
   if 'aoff' in data:
      _data['aoff'] = data['aoff']
      del data['aoff']


      
   if key and basecfg and getattr(parser,'parse_basecfg',None):
      st = mod.parse_basecfg(basecfg,_data)

   if st:
      st['version']=version
      st['family'] = type
   
      if st.get('v',None) and st['v'] != type:
         st['family'] = st['v']
         
      if st.get('v',None):
         del st['v']


      if type =='vmzeus' and version >= "02.00.00.00":
         st['family'] = 'vmzeus2'
               
      if md5:
         st['binary'] = md5
                  
      try:
         print json.dumps(st, sort_keys=False, indent=2, separators=(',', ': '))
      except:
         import pprint
         pprint.pprint(st)
         ### save static config in db
      db.remember(st)
      del st['datahash']
      del st['timestamp']
      del st['_id']
                                                      
      return json.dumps(st)
   

if __name__ == '__main__':
   run(host='0.0.0.0', port=8181)

