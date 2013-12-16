from libs.structure import DataStructure,StructList
from libs.structure import c_byte,c_word,c_dword,c_qword
from libs.kdNRV2b import inflate as unrv2b

class Header(DataStructure):
    _have_data = False
    _fields_ = [('rand',c_byte*20),('size',c_dword),('flags',c_dword),('count',c_dword),('md5',c_byte*0x10)]

    def _print_md5(self):
        ret =''
        for i in range(0,0x10):
            ret += '%02x' % self.md5[i]
        return ret



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
            return 'ID: %s' % self._cfgids[self.id]
        return 'ID: %d' % self.id

    def feed(self,data):
        super(Item,self).feed(data)

        if self.flags & self._flags['ITEMF_COMPRESSED'] and\
           self.realSize != self.size:
            self.decompress()

    def decompress(self):
        self.data = unrv2b(self.data,self.realSize).run(1)

    def is_option(self):
        return self.flags & self._flags['ITEMF_IS_OPTION'] 

    def is_inject(self):
        return self.flags & self._flags['ITEMF_IS_HTTP_INJECT'] 

    def is_setting(self):
        return self.flags & self._flags['ITEMF_IS_SETTING'] 

    def is_injectlist(self):
        return self.id == self._cfgids_n['CFGID_HTTP_INJECTS_LIST']

    def is_webfilter(self):
        return self.id == self._cfgids_n['CFGID_HTTP_FILTER'] 
   
    def is_cfg_url(self):
        return self.id == self._cfgids_n['CFGID_URL_SERVER_0']    

    def is_acfg_url(self):
        return self.id == self._cfgids_n['CFGID_URL_ADV_SERVERS']    

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
        return 'FLAGS %x' % self.flags
  
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

class HttpInject_HList(StructList):
    struct = HttpInject_Header
