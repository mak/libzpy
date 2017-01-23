from Crypto.Cipher import AES
import structs.chthonic as cht
import fmt.zeus as zeusfmt
from libs.basecfg import BaseCfg
from libs.vmzeus import VmContext as VM
from . import template as t
import json
import re
import sys
import StringIO
import hashlib


def unpack(data, verb, key):
    if key is not None:
        data = aesdecrypt(data, key)
    data = t.unpack(data, verb, cht)

    result = []
    items = data['items']
    for item in items:
        if item.id == 0x2ee3:
            nested = unpack(item.data, verb, key)
            result += nested['items']
        elif item.id == 0x2ee0 and item.flags:
            nested = unpack(item.data, verb, None)
            result += nested['items']
        elif item.id == 0x97780db2:
            nested = unpack(item.data, verb, None)
            result += nested['items']
        else:
            result.append(item)
    data['items'] = result
    return data


def parse(data, verb):
    return t.parse(data, verb, cht)


def to_str(data, verb):
    if not isinstance(data, dict):
        verb('I need unpacked data')
        return

    fmt = zeusfmt.fmt(data)
    fmt._ = 'Cthonic'
    return fmt.format()

def aesdecrypt(data, key):
    aes = AES.new(key, AES.MODE_ECB)
    data = aes.decrypt(data)
    return '\x00' + ''.join(chr(ord(x0) ^ ord(x1)) for x0, x1 in zip(data[1:], data[:-1]))

def go(data, verb, aeskey):
    aeskey = aeskey.decode('hex')

    data = unpack(data, verb, aeskey)
    data = parse(data, verb)
    print to_str(data, verb)


def format(data, verb, type='pretty'):
    if type == 'pretty':
        return to_str(data, verb)
    elif type == 'json':
        return json.dumps(data)

def get_basecfg(data,verb,*args):
    oldstdout = sys.stdout
    sys.stdout = StringIO.StringIO()
    cfg = None
    try:
        vmctx = VM(data['code'].decode('hex'),data['data'].decode('hex'))
        vmctx._fix_xors(data['magic'])
        vmctx.run()
        cfg = vmctx.config

    except Exception as e:
        import traceback
        sys.stdout = oldstdout
        print 'VMError: ' + `e`
        traceback.print_exc(file=sys.stdout)

    sys.stdout = oldstdout
    if not cfg:
        print 'Code hash: ' + hashlib.md5(data['code'].decode('hex')).hexdigest()
        print 'Data hash: ' + hashlib.md5(data['data'].decode('hex')).hexdigest()
        print 'Xors: ' + str(data['magic'])
    return cfg


class ChthonicCfg(BaseCfg):
    def __init__(self, cfg):
        super(ChthonicCfg, self).__init__(cfg)
        self.rc4sbox = 'huh'

    def get_ua(self):
        self.ua = re.search("(Moz[^\x00]+)\x00", self.cfg).group(1)
        return self.ua

    def get_basics(self):
        st = super(ChthonicCfg, self).get_basics()
        st['user-agent'] = self.get_ua()
        del st['rc4sbox']
        return st

def parse_basecfg(basecfg, _args):
   cfg  = ChthonicCfg(basecfg)
   return cfg.get_basics()
