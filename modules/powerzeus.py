import structs.powerzeus as pz
import fmt.powerzeus as pzfmt

from StringIO import StringIO
from ctypes import sizeof
import json

def unpack(data,verb):
    data=  StringIO(data)
    stor = pz.Header(data)
    ret= {}
    ret['header'] = stor
    ret['items'] = []
    for idx in range(stor.count):
        itm = pz.Item(data)
        ret['items'].append(itm)
    return ret


def parse(data,verb):
    if not isinstance(data,dict):
        verb('I need unpacked data')
        return
    ret = {}
    ret['header'] = data['header']
    
    injList = []
    injects = []

    for itm in data['items']:
        if itm.is_webfilter():
            if not 'webfilters' in ret:
                ret['webfilters'] = []
            for x in filter(None,itm.data.split("\x00")):
                ret['webfilters'].append(x)

        elif itm.is_injectlist():
            injList.append(itm)
        elif itm.is_inject():
            injects.append(itm)

        elif itm.is_captchasrv():

            if not 'captcha_srv' in ret:
                ret['captcha_srv'] = []
            ret['captcha_srv'].append(itm.data)

        elif itm.is_captchalist():

            if not 'captcha_lst' in ret:
                ret['captcha_lst'] = []
            
            x = pz.HttpInject_Captcha(itm.data)
            u = x.data[x.urlCaptcha:].replace("w\x00\x00","www").strip("\x00")
            m = x.data.replace("w\x00\x00","www")
            m = m[x.urlHostMask:m.find("\x00")]
            ret['captcha_lst'].append({'mask':m,'url':u})

        elif itm.is_notifysrv():

            if not 'notify_srv' in ret:
                ret['notify_srv'] = []
            ret['notify_srv'].append(itm.data)


        elif itm.is_cfg_url():

            if not 'server' in ret:
                ret['server'] = []
            ret['server'].append(itm.data)

        elif itm.is_acfg_url():
            if not 'advance' in ret:
                ret['advance'] = []
            ret['advance'].append(itm.data)
        else:
            print str(itm)

    ret['injects'] = []
    for il in injList:
        idx  = 0
        for ih in pz.HttpInject_HList(il.data):
            rr = {}
            rr['meta']  = {}
            rr['target']=str(ih.data).strip().replace("\x00",'')
            if ih.is_inject():
                t = 'injects'
            elif ih.is_capture(): t = 'captures'
            rr[t]= []
            idx2= 0 
            r = {}
            for inj in pz.HttpInject_BList(injects[idx].data):
                if idx2 % 3 == 0:
                    r['pre'] = inj.data
                elif idx2 % 3 == 1:
                    r['post'] = inj.data
                else:
                    r['inj'] = inj.data
                    rr[t].append(r)
                    r= {}
                idx2+=1
            idx += 1
            ret['injects'].append(rr)
    return ret
       


def to_str(data,verb):
    if not isinstance(data,dict):
        verb('I need unpacked data')
        return


    fmt = pzfmt.fmt(data)
    print fmt.server()

    print fmt.notify_srv()
    print fmt.notify_list()

    print fmt.captcha_srv()
    print fmt.captcha_list()

    
    print fmt.webfilters() + "\n\n"
    print fmt.injects()
    print fmt.captures()
    
    

        
def format(data,verb,type='pretty'):
    if type == 'pretty':
        return to_str(data,verb)
    elif type == 'json':
        return json.dumps(data)
