from libzpy.libs.structure import DataStructure,StructList
from libzpy.libs.structure import c_word
import libzpy.structs.zeus as zeus

class Header(zeus.Header):
    pass


class Item(zeus.Item):
    def __init__(self,*args,**kwargs):
        super(Item,self).__init__(*args,**kwargs)

        self._cfgids['CFGID_OUTER_PAYLOAD']      =  12003
        self._cfgids['CFGID_INJECTS']            =  2541227442
        self._cfgids['CFGID_PAYLOAD']            =  12000
        self._flags['ITEMF_IS_PACKED_CONFIG']    =  0x10000000


class HttpInject_HList(zeus.HttpInject_HList):
    struct = zeus.HttpInject_Header

class HttpInject_BList(zeus.HttpInject_BList):
    pass

class HttpInject_Captcha(DataStructure):
    _fields_ = [('size',c_word),('urlHostMask',c_word),('urlCaptcha',c_word)]

class WebFilter(zeus.WebFilter):
    def __init__(self,*args,**kwargs):
        super(WebFilter,self).__init__(*args,**kwargs)
        self._wf['$'] = 'NOTIFY'
        self._wf['|'] = 'UNKNOWN' ## TODO....