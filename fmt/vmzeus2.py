import  fmt.zeus as zeus
from struct import unpack
from datetime import datetime
class fmt(zeus.fmt):

    def notify_srv(self):
        return self._list('{{NOTIFY_SERVERS}}','notify_srv')
    def notify_list(self):
        return self._list('{{NOTIFY_LIST}}','notify_lst')


    def captcha_list(self):
        return self._list('{{CAPTCHA_LIST}}','captcha_lst')
        
    def captcha_srv(self):
        return self._list('{{CAPTCHA_SERVERS}}','captcha_srv')
         

    def ctime(self):
        if 'CFGID_CONFIG_CREATION_TIME' in self.cfg:
            return 'Creation Time: %s\n' % datetime.fromtimestamp(unpack('I',self.cfg['CFGID_CONFIG_CREATION_TIME'])[0])
        return ''
        
    def modvnc(self):
        if 'CFGID_VNCDLL_URL' in self.cfg:
            return '{{VNCDLL_URL}}\n' +self.cfg['CFGID_VNCDLL_URL'] + "\n{{END_VNCDLL_URL}}\n"
        return ''

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
        r += self.webfilters() 
        r += self.injects()
        r += self.captures()
        return r
