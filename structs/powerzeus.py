from libs.structure import DataStructure,StructList
from libs.structure import c_word
import structs.zeus as zeus

class Header(zeus.Header):
    pass

class Item(zeus.Item):

    def __init__(self,*args,**kwargs):
        super(Item,self).__init__(*args,**kwargs)
        self._flags['ITEMF_IS_ARGUMENT']       =  0x00100000
        self._flags['ITEMF_IS_MODULE_HASH']    =  0x00200000
        self._flags['ITEMF_IS_PROC_NAME_HASH'] =  0x00400000
        self._cfgids[20009] = 'CFGID_CAPTCHA_SERVER'
        self._cfgids[20010] ='CFGID_CAPTCHA_LIST'
        self._cfgids[20011] ='CFGID_NOTIFY_SERVER'
        self._cfgids[20012] ='CFGID_NOTIFY_LIST'
        self._cfgids[20013] ='CFGID_REFRESH_BLOCK_LIST'
        self._cfgids_n = self._cfgids.__class__(map(reversed, self._cfgids.items()))


    def is_captchasrv(self):
        return self.id == self._cfgids_n['CFGID_CAPTCHA_SERVER']

    def is_captchalist(self):
        return self.id == self._cfgids_n['CFGID_CAPTCHA_LIST']
    def is_notifysrv(self):
        return self.id == self._cfgids_n['CFGID_NOTIFY_SERVER']

    def is_notifylist(self):
        return self.id == self._cfgids_n['CFGID_NOTIFY_LIST']

_http_inj_flags = {
    'FLAG_IS_INJECT'                : 0x0001, 
    'FLAG_IS_CAPTURE'               : 0x0002, 
    'FLAG_REQUEST_POST'             : 0x0004,
    'FLAG_REQUEST_GET'              : 0x0008,
    'FLAG_ONCE_PER_DAY'             : 0x0010, 
    'FLAG_CAPTURE_NOTPARSE'         : 0x0100, 
    'FLAG_CAPTURE_TOFILE'           : 0x0200, 
    'FLAG_URL_CASE_INSENSITIVE'     : 0x1000, 
    'FLAG_CONTEXT_CASE_INSENSITIVE' : 0x2000 
}
class HttpInject_InjectBlock(zeus.HttpInject_InjectBlock):
    _flags = _http_inj_flags

class HttpInject_Header(DataStructure):
    _pack_ = 1
    _fields_ = [('flags',c_word),('size',c_word),('urlMask',c_word),
                ('postDataBlackMask',c_word),('postDataWhiteMask',c_word),
                ('contextMask',c_word)
                ]
    _flags = _http_inj_flags 

    def is_inject(self):
        return self.flags & self._flags['FLAG_IS_INJECT']
    def is_capture(self):
        return self.flags & self._flags['FLAG_IS_CAPTURE']

class HttpInject_HList(zeus.HttpInject_HList):
    struct = HttpInject_Header

class HttpInject_BList(zeus.HttpInject_BList):
    pass

class HttpInject_Captcha(DataStructure):
    _fields_ = [('size',c_word),('urlHostMask',c_word),('urlCaptcha',c_word)]


class WebFilter(zeus.WebFilter):
    def __init__(self,*args,**kwargs):
        super(WebFilter,self).__init__(*args,**kwargs)
        self._wf['$'] = 'NOTIFY'
