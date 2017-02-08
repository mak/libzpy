import libzpy.structs.zeus as zeus
import libzpy.fmt.zeus as zfmt
from libzpy.modules import template as t

from libzpy.libs.basecfg import BaseCfg
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
    fmt._ = 'flokibot'
    return fmt.format()


def json(data):
    verb=lambda x:x
    data = unpack(data,verb,True)
    data = parse(data,verb)
    return data


def go(data,verb):
    data = unpack(data,verb)
    data = parse(data,verb)
    print to_str(data,verb)


def format(data,verb,type='pretty'):
    if type == 'pretty':
        return to_str(data,verb)
    elif type == 'json':
        return json.dumps(data)


def parse_basecfg(basecfg,args):
    bc = BaseCfg(basecfg)
    bc.get_rc4(581)
    res = bc.get_basics()
    return res


def get_basecfg(d,*args):
    return d.decode('hex')
