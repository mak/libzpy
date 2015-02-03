import  fmt.zeus as zeus


class fmt(zeus.fmt):
            
    def __init__(self,*args,**kwargs):
        super(fmt,self).__init__(*args,**kwargs)
        self._wf_butify['#'] = 'MOVIE'
        fmts  = self._formats[:4]
        fmts  += ['webinj_url','cmds','keyloger','video','httpvip','dns_filter']
        fmts  += self._formats[4:]
        self._formats = fmts


    def dns_filter(self):
        return self._list('DNS_FILTERS','dns_filter')

    def cmds(self):
        return self._list('COMANDS_LIST','cmds')

    def keyloger(self):
        if 'keyloger' in self.cfg:
            return '{{KEYLOGER}}\nTargets: %s\nTime: %d\n{{END_KEYLOGER}}\n' % (self.cfg['keyloger'],self.cfg['keyloger_time'])
        return ''
    
    def video(self):
        if 'video_qual' in self.cfg:
            return '{{VIDEO}}\nQuality: %d | Length: %d\n{{END_VIDEO}}\n' % (self.cfg['video_qual'],self.cfg['video_length'])
        return ''

    def httpvip(self):
        return self._list('HTTPVIPURLS','httpvip')

    def webinj_url(self):
        return self._field('WEBINJECT_URL','webinj_url')
