from libs.structure import DataStructure
import structs.zeus as zeus

class Header(zeus.Header):
    pass

class Item(zeus.Item):

    def __init__(self,*args,**kwargs):
        super(Item,self).__init__(*args,**kwargs)
        self._flags['ITEMF_IS_ARGUMENT']       =  0x00100000
        self._flags['ITEMF_IS_MODULE_HASH']    =  0x00200000
        self._flags['ITEMF_IS_PROC_NAME_HASH'] =  0x00400000

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

class HttpInject_Header(zeus.HttpInject_Header):
    _flags = _http_inj_flags 
