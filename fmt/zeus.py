
class fmt(object):
    _name = 'ZeuS'
    _formats = ['version','server','adv_server','webfilters','injects','captures']
    def __init__(self,cfg):
        self.cfg = cfg

    _wf_butify={
        '@' : 'SCREENSHOT',
        '!' : 'DONT-REPORT',
        '-' : 'SAVE-COOCKIE',
        '^' : 'BLOCK-ACCESS'
    }
        
    def _butify_wf(self,d):
        data = d.strip()
        if data[0] in self._wf_butify:
            return '{{' + self._wf_butify[data[0]] + '}} ' + data[1:]
        return data

    def webfilters(self):
        if 'webfilters' in self.cfg:
            return "{{WEBFILTERS}}\n" + "\n".join(map(self._butify_wf,self.cfg['webfilters'])) + "\n{{END_WEBFILTERS}}\n\n"
        else:
            return ''

    def _field(self,name,fname):
        if not fname in self.cfg:
            return ''
        return '{{%s}}\n%s\n{{END_%s}}\n'%(name,str(self.cfg[fname]),name)

    def _list(self,name,fname):
        if not fname in self.cfg:
            return ''
        r =  '{{%s}}\n'%name
        for c in self.cfg[fname]:
            if isinstance(c,str):
                r +=  c + "\n"
            elif isinstance(c,dict):
                for n in c:
                    r += n.upper() + ':' + c[n] + "  "
                r += "\n"
        return r + "{{END_%s}}\n"%name
        
    def version(self):
        if 'version' in self.cfg:
            return "\n\n" + self._name + ': ' +  self.cfg['version'] + "\n\n\n"
        return ''

    def binary(self):    
        return self._list('UPDATE_URLS','update')
    # def binary(self):    
    #     return self._list("{{UPDATE_URLS}}",'update',"{{END_UPDATE_URLS}}")

    def server(self):    
        return self._list('SERVER_URLS','server')

    def adv_server(self): 
        return self._list('ADV_SERVER_URLS','advance')

    def inject_flags(self,inj):
        pass

    def injects(self):
        r = self._injects_fmt('injects')
        return ('{{INJECTS}}' +r + "{{END_INJECTS}}\n") if r else ''

    def captures(self):
        r = self._injects_fmt('captures')
        return ('{{CAPTURES}}' +r + "{{END_CAPTURES}}\n") if r else ''

    def _injects_fmt(self,t):
        r = '' #
        for inject in self.cfg['injects']:
            if t in inject:
                r += '\nTarget: ' + inject['target'] 
                r += '\nFlags: ' + inject['flags']
                r += '\nMeta: '
                r += "\n"
                for inj in inject[t]:

                    r += "{{DATA_BEFORE}}"+ (" {{FLAGS: %X}}" % inj['pre_flag']) +"\n"
                    r += inj['pre'] + "\n"
                    r += "{{END_DATA_BEFORE}}\n"
                    r += "{{DATA_AFTER}}" + (" {{FLAGS: %X}}" % inj['post_flag']) + "\n"
                    r += inj['post'] + "\n"
                    r += "{{END_DATA_AFTER}}\n"
                    r += "{{INJECT}}"+ (" {{FLAGS: %X}}" % inj['inj_flag']) +"\n" 
                    r += inj['inj'] + "\n"
                    r += "{{END_INJECT}}\n\n"
                    r += '-'*32
                    r +="\n"
                r += '#' * 32
                r +="\n"
        return r 

    def format(self):
        r = ''
        for fmt in self._formats:
            r+=getattr(self,fmt)()

        return r
