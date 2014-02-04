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
#        self._cfgids[20013] ='CFGID_REFRESH_BLOCK_LIST'
        self._cfgids_n = self._cfgids.__class__(map(reversed, self._cfgids.items()))


    def is_captchasrv(self):
        return self.id == self._cfgids_n['CFGID_CAPTCHA_SERVER']

    def is_captchalist(self):
        return self.id == self._cfgids_n['CFGID_CAPTCHA_LIST']
    def is_notifysrv(self):
        return self.id == self._cfgids_n['CFGID_NOTIFY_SERVER']

    def is_notifylist(self):
        return self.id == self._cfgids_n['CFGID_NOTIFY_LIST']


# class HttpInject_InjectBlock(zeus.HttpInject_InjectBlock):
#     pass

class HttpInject_HList(zeus.HttpInject_HList):
    struct = zeus.HttpInject_Header

class HttpInject_BList(zeus.HttpInject_BList):
    pass

class HttpInject_Captcha(DataStructure):
    _fields_ = [('size',c_word),('urlHostMask',c_word),('urlCaptcha',c_word)]
