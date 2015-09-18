import  fmt.zeus as zeus


class fmt(zeus.fmt):
            
    def __init__(self,*args,**kwargs):
        super(fmt,self).__init__(*args,**kwargs)
        fmts  = self._formats[:4]
        fmts  += ['notify_srv','notify_list','captcha_srv','captcha_list']
        fmts  += self._formats[4:]
        self._formats = fmts


    def notify_srv(self):
        return self._list('NOTIFY_SERVERS','notify_srv')
    def notify_list(self):
        return self._list('NOTIFY_LIST','notify_lst')

    def captcha_list(self):
        return self._list('CAPTCHA_LIST','captcha_lst')
        
    def captcha_srv(self):
        return self._list('CAPTCHA_SERVERS','captcha_srv')
