
class fmt(object):

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
        return "\n".join(map(self._butify_wf,self.cfg['webfilters']))

    def _list(self,pre,name,post):
        if not name in self.cfg:
            return ''
        r =  pre + "\n"
        for c in self.cfg[name]:
            if isinstance(c,str):
                r +=  c + "\n"
            elif isinstance(c,dict):
                for n in c:
                    r += n.upper() + ':' + c[n] + "  "
                r += "\n"
        return r + post + "\n"
        

    def server(self):    
        return self._list("{{SERVER_URLS}}",'server',"{{END_SERVER_URLS}}")

    def adv_server(self):    
        return self._list("{{ADV_SERVER_URLS}}",'advance',"{{ADV_END_SERVER_URLS}}")

    def injects(self):
        r = '{{INJECTS}}'
        for inject in self.cfg['injects']:
            if 'injects' in inject:
                r += '\nTarget: ' + inject['target'] 
                r += '\nMeta:'  
                r += "\n"
                for inj in inject['injects']:

                    r += "{{DATA_BEFORE}}\n"
                    r += inj['pre'] + "\n"
                    r += "{{END_DATA_BEFORE}}\n"
                    r += "{{DATA_AFTER}}\n"
                    r += inj['post'] + "\n"
                    r += "{{END_DATA_AFTER}}\n"
                    r += "{{INJECT}}\n"
                    r += inj['inj'] + "\n"
                    r += "{{END_INJECT}}\n\n"
                    r += '-'*32
                    r +="\n"
                r += '#' * 32
                r +="\n"
        return r + "{{END_INJECTS}}\n"

    def captures(self):
        r= "{{CAPTURES}}\n"
        for inject in self.cfg['injects']:
            if 'captures' in inject:
                r += 'Target: ' + inject['target']
                r += 'Meta:'
                for inj in inject['captures']:
                    r += "{{DATA_BEFORE}}\n"
                    r += inj['pre'] + "\n"
                    r += "{{END_DATA_BEFORE}}"
                    r += "{{DATA_AFTER}}\n"
                    r += inj['post'] + "\n"
                    r += "{{END_DATA_AFTER}}\n"
                    r += "{{INJECT}}\n"
                    r += inj['inj'] + "\n"
                    r += "{{END_INJECT}}\n\n"
                    r += '-'*32 
                    r += "\n"
                r += '#' * 32
                r +="\n"
        return r + "{{END_CAPTURES}}\n"        
