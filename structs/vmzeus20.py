from libs.structure import DataStructure,StructList
from libs.structure import c_dword,c_word
import structs.zeus as zeus


class Header(DataStructure):
    _have_data=False
    _fields_ = [ ('unk1',c_dword), ('size',c_dword), ('flags',c_dword), ('unk2',c_dword),('count',c_dword),('checksum',c_dword),('unk3',c_dword)]



class Item(zeus.Item):

    def __init__(self,*args,**kwargs):
        super(Item,self).__init__(*args,**kwargs)
        self._flags['ITEMF_IS_ARGUMENT']       =  0x00100000
        self._flags['ITEMF_IS_MODULE_HASH']    =  0x00200000
        self._flags['ITEMF_IS_PROC_NAME_HASH'] =  0x00400000
        self._flags['ITEMF_IS_HTTP_INJECT'] = 8
        self._cfgids[20009] = 'CFGID_CAPTCHA_SERVER'
        self._cfgids[20010] ='CFGID_CAPTCHA_LIST'
        self._cfgids[20011] ='CFGID_NOTIFY_SERVER'
        self._cfgids[20012] ='CFGID_NOTIFY_LIST'
        self._cfgids[20013] ='CFGID_REFRESH_BLOCK_LIST'
        self._cfgids[20014] ='CFGID_VNCDLL_URL'
        self._cfgids[20015] ='CFGID_MINERDLL_URL'
        self._cfgids[20018] ='CFGID_SPAM_TASK'
        self._cfgids[20019] ='CFGID_SPAM_TASK_STATUS'
        self._cfgids[20020] ='CFGID_SPAM_MODULE_URL'
        self._cfgids[20021] ='CFGID_CONFIG_CREATION_TIME'
        self._cfgids[20022] ='CFGID_P2P_NODE_INFO'
        self._cfgids[20023] ='CFGID_SIGNATURE'
        self._cfgids[20024] ='CFGID_FORCED_HOMEPAGE'

#        self._cfgids[20013] ='CFGID_REFRESH_BLOCK_LIST'
        self._cfgids_n = self._cfgids.__class__(map(reversed, self._cfgids.items()))
        args[0].read(4)

    def is_captchasrv(self):
        return self.id == self._cfgids_n['CFGID_CAPTCHA_SERVER']

    def is_captchalist(self):
        return self.id == self._cfgids_n['CFGID_CAPTCHA_LIST']
    def is_notifysrv(self):
        return self.id == self._cfgids_n['CFGID_NOTIFY_SERVER']

    def is_notifylist(self):
        return self.id == self._cfgids_n['CFGID_NOTIFY_LIST']

    def is_ctime(self):
        return self.id == self._cfgids_n['CFGID_CONFIG_CREATION_TIME']

# class HttpInject_InjectBlock(zeus.HttpInject_InjectBlock):
#     pass

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
