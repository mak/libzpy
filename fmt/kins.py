import  fmt.zeus as zeus


class fmt(zeus.fmt):
            
    def __init__(self,*args,**kwargs):
        super(fmt,self).__init__(*args,**kwargs)
        self._wf_butify['$'] = 'NOTIFY'
        self._wf_butify['|'] = 'UNKNOWN' ## TODO....

    def notify_srv(self):
        return self._list('{{NOTIFY_SERVERS}}','notify_srv','{{END_NOTIFY_SERVERS}}')
    def notify_list(self):
        return self._list('{{NOTIFY_LIST}}','notify_lst','{{END_NOTIFY_LIST}}')

    def captcha_list(self):
        return self._list('{{CAPTCHA_LIST}}','captcha_lst','{{END_CAPTCHA_LIST}}')
        
    def captcha_srv(self):
        return self._list('{{CAPTCHA_SERVERS}}','captcha_srv','{{END_CAPTCHA_SERVERS}}')
