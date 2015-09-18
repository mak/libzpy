from StringIO import StringIO
from ctypes import sizeof
from hashlib import md5

def unpack(data,verb,mod=None,verify=None):
    hash=md5(data[:sizeof(mod.Header)]).digest()
    data2=data
    data=  StringIO(data)
    stor =mod.Header(data)
    if verify:
#        print str(bytearray(stor.md5)).encode('hex')
#        print hash.encode('hex')
        if hash != str(bytearray(stor.md5)):
            print '[-] Hash mismath -- corrupted binstor?'
#@            with open('/tmp/ffffap','wb') as f: f.write(data2)
            return None

    ret= {}
    ret['header'] = stor
    ret['items'] = []
    for idx in xrange(stor.count):
        itm = mod.Item(data)
        ret['items'].append(itm)
    return ret

def string_list(d):
    return filter(None,d.split("\x00"))

    

def parse(data,verb,mod=None):
    if not isinstance(data,dict):
        verb('I need unpacked data')
        return
    ret = {}
    ret['header'] = data['header']
    ret['unknown'] = {}
    injList = []
    injects = []

    for itm in data['items']:
        if itm.is_webfilter():
            if not 'webfilters' in ret:
                ret['webfilters'] = []
            for x in filter(None,itm.data.split("\x00")):
                ret['webfilters'].append(mod.WebFilter(x).json())

        elif itm.is_injectlist():
            injList.append(itm)
        elif itm.is_inject():
            injects.append(itm)

#        elif itm.is_dnslist()

        elif itm.is_update():
            if not 'update' in ret:
                ret['update'] = []
            ret['update'].append(itm.data)

        elif itm.is_version():
            pv =lambda x:'.'.join(['%.2X'% ord(c) for c in reversed(x)])
            ret['version'] =  pv(itm.data)

        elif (hasattr(itm,'is_captchasrv' ) and itm.is_captchasrv()):

            if not 'captcha_srv' in ret:
                ret['captcha_srv'] = []
            ret['captcha_srv'].append(itm.data)

        elif (hasattr(itm,'captchalist') and itm.is_captchalist()) :

            if not 'captcha_lst' in ret:
                ret['captcha_lst'] = []
            
            x = mod.HttpInject_Captcha(itm.data)
            u = x.data[x.urlCaptcha:].replace("w\x00\x00","www").strip("\x00")
            m = x.data.replace("w\x00\x00","www")
            m = m[x.urlHostMask:m.find("\x00")]
            ret['captcha_lst'].append({'mask':m,'url':u})

        elif (hasattr(itm,'notifysrv') and itm.is_notifysrv()):

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
            ret['advance'] += itm.data.split("\x00")
        
        elif itm._str_field('id')[1] != str(itm.id):
#            ## we know this type...
            ret[itm._str_field('id')[1]] = itm.data
        else:
            ret['unknown'][itm.id] = itm.data
#            ret['unknown'].append( str(itm) + "\n" + `itm.data`)

    ret['injects'] = []
    for il in injList:
        idx  = 0
        for ih in mod.HttpInject_HList(il.data):

            rr = {}
            rr['flags'] = ih._print_flags().strip()
            rr['flags_raw'] = ih.flags
            rr['meta']  = {} #{'flags': hex(ih.flags)}
            rr['target']=str(ih.data).strip().replace("\x00",'')
            if ih.is_inject():
                t = 'injects'
            elif ih.is_capture(): t = 'captures'
            else: t='unknown'
            rr[t]= []
            idx2= 0 
            r = {}
            for inj in mod.HttpInject_BList(injects[idx].data):
                if idx2 % 3 == 0:
                    r['pre'] = unicode(inj.data,'utf-8','replace').strip()
                    r['pre_flag'] = inj.flags
                elif idx2 % 3 == 1:
                    r['post'] = unicode(inj.data,'utf-8','replace').strip()
                    r['post_flag'] = inj.flags
                else:
                    r['inj'] = unicode(inj.data,'utf-8','replace').strip()
                    r['inj_flag'] = inj.flags
                    rr[t].append(r)
                    r= {}
                idx2+=1
            idx += 1
            ret['injects'].append(rr)
    return ret
       
