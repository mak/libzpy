from libs.structure import DataStructure,StructList
from libs.structure import c_byte,c_word,c_dword,c_qword,c_wchar,c_char
from libs.kdNRV2b import inflate as unrv2b
from libs.UCL import UCL
#from ctypes import bytearray

_UCL = None
def decompress(data,size):
    global _UCL
    if not _UCL:
        _UCL = UCL()
    return _UCL.decompress(data,size)


class Header(DataStructure):
    _have_data = False
    _fields_ = [('rand',c_byte*20),('size',c_dword),('flags',c_dword),('count',c_dword),('md5',c_byte*0x10)]

    def _print_md5(self):
        ret =''
        for i in range(0,0x10):
            ret += '%02x' % self.md5[i]
        return ret

class PESettings(DataStructure):
    compId = None
    _have_data = False
    _pack_ =1
    _fields_ = [('size',c_dword),('_compId',c_wchar*60),('guid',c_char*0x10),('_RC4KEY',c_byte*0x102),
                ('exeFile',c_char*20),('reportFile',c_char*20),('regKey',c_char*10),('regDynamicConfig',c_char*10),
                ('regLocalConfig',c_char*10),('regLocalSettings',c_char*10),('processInfectionId',c_dword),('storageArrayKey',c_dword)
    ]

    def _print__compId(self):
        return 'compId: ' + self.compId
    def _print__RC4KEY(self):
        b = bytearray(self._RC4KEY)
        return str(b).encode('hex')

    def __getattribute__(self,name):
        if name=='compId':
            return self._compId if self._compId[0].__class__ == unicode else ''.join(map(lambda x:x[0],self._compId)).strip("\x00")
        elif name == 'RC4KEY':
            return self._print__RC4KEY()
        else:
            return object.__getattribute__(self, name)

class Item(DataStructure):
    _flags = {
        'ITEMF_COMPRESSED': 0x00000001,
        'ITEMF_COMBINE_ADD':  0x00010000,
        'ITEMF_COMBINE_OVERWRITE':0x00020000,
        'ITEMF_COMBINE_REPLACE'  :0x00040000, 
        'ITEMF_COMBINE_DELETE'   :0x00080000,
        'ITEMF_IS_OPTION'         :0x10000000,
        'ITEMF_IS_SETTING'        :0x20000000, 
        'ITEMF_IS_HTTP_INJECT'    :0x40000000

    }

    _cfgids = {
        20001 :'CFGID_LAST_VERSION',
        20002 :'CFGID_LAST_VERSION_URL',
        20003 :'CFGID_URL_SERVER_0',
        20004 :'CFGID_URL_ADV_SERVERS',
        20005 :'CFGID_HTTP_FILTER',
        20006 :'CFGID_HTTP_POSTDATA_FILTER',
        20007 :'CFGID_HTTP_INJECTS_LIST',
        20008 :'CFGID_DNS_LIST',
    }

    _fields_ = [ ('id',c_dword),('flags',c_dword),('size',c_dword),('realSize',c_dword)]

    def __init__(self,*args,**kwargs):
        super(Item,self).__init__(*args,**kwargs)
        self._cfgids_n = self._cfgids.__class__(map(reversed, self._cfgids.items()))

    def _print_id(self):
        if self.id in self._cfgids:
            return '%s' % self._cfgids[self.id]
        return '%d' % self.id

    def feed(self,data):
        super(Item,self).feed(data)

        ## apperently we ca have decompression without changed size...
        if self.flags & self._flags['ITEMF_COMPRESSED']:
           self.decompress()

    def decompress(self):
        self.data = decompress(self.data,self.realSize)#.run(1)
#        self.data = unrv2b(self.data,self.realSize).run(1)


    def is_compresed(self):
        return self.flags & self._flags['ITEMF_COMPRESSED'] 

    def is_option(self):
        return self.flags & self._flags['ITEMF_IS_OPTION'] 

    def is_inject(self):
        return self.flags & self._flags['ITEMF_IS_HTTP_INJECT'] 

    def is_setting(self):
        return self.flags & self._flags['ITEMF_IS_SETTING'] 

    def is_version(self):
        return self.id == self._cfgids_n['CFGID_LAST_VERSION']

    def is_update(self):
        return self.id == self._cfgids_n['CFGID_LAST_VERSION_URL']                

    def is_injectlist(self):
        return self.id == self._cfgids_n['CFGID_HTTP_INJECTS_LIST']

    def is_webfilter(self):
        return self.id == self._cfgids_n['CFGID_HTTP_FILTER'] 
   
    def is_cfg_url(self):
        return self.id == self._cfgids_n['CFGID_URL_SERVER_0']    

    def is_acfg_url(self):
        return self.id == self._cfgids_n['CFGID_URL_ADV_SERVERS']    

    def is_dnslist(self):
        return self.id == self._cfgids_n['CFGID_DNS_LIST']

    def is_dnsfilter(self):
        return self.id == self._cfgids_n['CFGID_DNS_FILTER']

    def is_cmdlist(self):
        return self.id == self._cfgids_n['CFGID_CMD_LIST']



_http_inj_Flags ={
        'FLAG_IS_FAKE'                  : 0x0001,
        'FLAG_IS_MIRRORFAKE'            : 0x0002,
        'FLAG_IS_INJECT'                : 0x0004,
        'FLAG_IS_CAPTURE'               : 0x0008,
        
        'FLAG_ONCE_PER_DAY'             : 0x0010,
        'FLAG_REQUEST_POST'             : 0x0020,
        'FLAG_REQUEST_GET'              : 0x0040,
        
        'FLAG_CAPTURE_NOTPARSE'         : 0x0100,
        'FLAG_CAPTURE_TOFILE'           : 0x0200, 
    
        'FLAG_URL_CASE_INSENSITIVE'     : 0x1000, 
        'FLAG_CONTEXT_CASE_INSENSITIVE' : 0x2000  
    }

class HttpInject_InjectBlock(DataStructure):
    _fields_ = [('size',c_word),('flags',c_word)]
    _flags  = _http_inj_Flags

    def _print_flags(self):
        return '%x' % self.flags
  
class HttpInject_BList(StructList):
    struct = HttpInject_InjectBlock


class HttpInject_Header(DataStructure):
    _pack_ = 1
    _fields_ = [('flags',c_word),('size',c_word),('urlMask',c_word),('fakeUrl',c_word),
                ('postDataBlackMask',c_word),('postDataWhiteMask',c_word),
                ('blockOnUrl',c_word),('contextMask',c_word)
                ]
    _flags = _http_inj_Flags 
    
    def is_inject(self):
        return self.flags & self._flags['FLAG_IS_INJECT']

    def is_capture(self):
        return self.flags & self._flags['FLAG_IS_CAPTURE']

class HttpInject_HList(StructList):
    struct = HttpInject_Header


class WebFilter(object):
    _wf = {
        '@' : 'SCREENSHOT',
        '!' : 'DONT-REPORT',
        '-' : 'SAVE-COOCKIE',
        '^' : 'BLOCK-ACCESS'
    }
    def __init__(self,d):
        self.act = d[0]
        self.trg = d[1:]
        if 0x61 < ord(self.act) < 0x7a:
            ## some strange shit...
            self.trg = self.act + self.trg
            self.act = ""

    
    def __getitem__(self,x):
        if x in self._wf:
            return self._wf[x]
        return x

    def json(self):
        return {'action':self[self.act],'target':self.trg}
