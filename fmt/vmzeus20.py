import  fmt.zeus as zeus
from struct import unpack
from datetime import datetime
class fmt(zeus.fmt):
            
    def __init__(self,*args,**kwargs):
        super(fmt,self).__init__(*args,**kwargs)
        self._wf_butify['$'] = 'NOTIFY'

    def notify_srv(self):
        return self._list('{{NOTIFY_SERVERS}}','notify_srv')
    def notify_list(self):
        return self._list('{{NOTIFY_LIST}}','notify_lst')


    def captcha_list(self):
        return self._list('{{CAPTCHA_LIST}}','captcha_lst')
        
    def captcha_srv(self):
        return self._list('{{CAPTCHA_SERVERS}}','captcha_srv')
         

    def ctime(self):
        key = 'CFGID_CONFIG_CREATION_TIME'
        if key in self.cfg:
            d = unpack('I',self.cfg[key])[0] if type(self.cfg[key]) == str else self.cfg[key] 
            return 'Creation Time: %s\n' % datetime.fromtimestamp(d)
        return ''
        
    def modvnc(self):
        return self._field('VNCDLL_URL','CFGID_VNCDLL_URL',lambda x:x)

    def signature(self):
        return self._field('SIGNATURE','CFGID_SIGNATURE',lambda x: x.encode('hex'))
    
    def format(self):
        r = ''
        r += self.version()
        r += self.ctime()
        r += self.server()
        r += self.modvnc()
        r += self.binary()
        r += self.adv_server()
        r += self.notify_srv()
        r += self.notify_list()
        r += self.captcha_srv()
        r += self.captcha_list()
        r += self.signature()
        r += self.webfilters() 
        r += self.injects()
        r += self.captures()
        return r
