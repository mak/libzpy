import structs.powerzeus as pz
from StringIO import StringIO
from ctypes import sizeof
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


def butify_wf(data):
    data = data.strip()
    if not data:
        return ''
    if data[0] == '@':
        return '{{SCREENSHOT}} ' + data[1:]
    elif data[0] == '!':
        return '{{BLOCK}} ' + data[1:]
    elif data[0] == '$':
        return '{{NOTIFY}} ' + data[1:]
    else:
        return data

def format(data,verb):
    if not isinstance(data,dict):
        verb('I need unpacked data')
        return

    webf = []
    injList = []
    injects = []
    cfgu = []
    acfgu = []
    for itm in data['items']:
        if itm.is_webfilter():
            webf.append(itm)
        elif itm.is_injectlist():
            injList.append(itm)
        elif itm.is_inject():
            injects.append(itm)
        elif itm.is_cfg_url():
            cfgu.append(itm)
        elif itm.is_acfg_url():
            cfgu.append(itm)

    
    print "{{CONFIG_URLS}}"
    for c in cfgu:
        print c.data
    print "{{END_CONFIG_URLS}}\n"

    print "{{ADV_CONFIG_URLS}}"
    for c in cfgu:
        print c.data
    print "{{END_ADV_CONFIG_URLS}}\n"
    

    print "{{WEBFILTERS}}"
    for w in  webf:
        print '\n'.join(filter(None,map(butify_wf,w.data.split("\x00"))))
    print "{{END_WEBFILTERS}}\n"
    print "injectsLen: %d" % len(injects)
    for il in injList:
        idx  = 0
        for ih in pz.HttpInject_HList(il.data):
            print "ID: %d" % (idx+1)
            print str(ih)
            print "Target: " + str(ih.data).strip().replace("\x00",'')
            if ih.is_inject():
                idx2= 0 
                for inj in pz.HttpInject_BList(injects[idx].data):
                    if idx2 % 3 == 0:
                        pre = "{{DATA_BEFORE}}"
                        post = "{{END_DATA_BEFORE}}"
                    elif idx2 % 3 == 1:
                        pre = "{{DATA_AFTER}}"
                        post= "{{END_DATA_AFTER}}"
                    else:
                        pre = "{{INJECT}}"
                        post= "{{END_INJECT}}"
                    idx2+=1
                    print pre
                    print inj.data
                    print post
                    
            print "#" *32
            idx += 1
            


        
