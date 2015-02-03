import libs.cr_tools as cry
import structs.zeus as zeus
import fmt.zeus as zfmt
from  . import template as t

from StringIO import StringIO
from ctypes import sizeof
from libs.basecfg import BaseCfg
import json

def unpack(data,verb,verify=False):
    return t.unpack(data,verb,zeus,verify)

def parse(data,verb):
    return t.parse(data,verb,zeus)
    
def to_str(data,verb):
    if not isinstance(data,dict):
        verb('I need unpacked data')
        return

    fmt = zfmt.fmt(data)
    fmt._ = 'PowerZeus'
    return fmt.format()


def json(data):
    verb=lambda x:x
    data = unpack(data,verb,True)
    data = parse(data,verb)
    return data
        
def go(data,verb):
    data = unpack(data,verb)
    data = parse(data,verb)
    #print `data['injects']`
    print to_str(data,verb)


def format(data,verb,type='pretty'):
    if type == 'pretty':
        return to_str(data,verb)
    elif type == 'json':
        return json.dumps(data)


def parse_basecfg(basecfg,args):
    data  = unpack(basecfg,lambda x: x,verify=False)
    data =  parse(data,lambda x:x)
    botname = data['unknown'][1].strip("\x00")
    rc4key  = data['unknown'][3].strip("\x00")
    urls    = data['unknown'][2].split('</>')[2:-1]
    return {'botname': botname, 'rc4key':rc4key,'urls':urls,'cfg':urls[0]}

    
    

## we allready decode basecfg
def get_basecfg(d,*args):
    # if not 'key' in args:
    #     pass

    k = args[0]
    d = d.decode('hex')
    return  cry.visDecry(cry.rc4decrypt(d,k,raw=True))

