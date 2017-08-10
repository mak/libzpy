from Crypto.Cipher import AES
import libzpy.structs.chthonic as cht
import libzpy.fmt.zeus as zeusfmt
from libzpy.libs.basecfg import BaseCfg
from libzpy.libs.vmzeus import VmContext as VM
from libzpy.modules import template as t
from libzpy.modules import zeus as zeus
import mlib.crypto as mc
import json
import re
import sys
import StringIO
import hashlib
import struct
import os
import libzpy.structs.chthonic as chtstruct

AES_BLOCK_SIZE = 16

def aes_pad(s):
    return s + (AES_BLOCK_SIZE - len(s) % AES_BLOCK_SIZE) * chr(AES_BLOCK_SIZE - len(s) % AES_BLOCK_SIZE)

def aes_decrypt(data, key):
    aes = AES.new(key, AES.MODE_ECB)
    data = aes.decrypt(data)
    data = mc.visDecry(data)
    return data

def aes_encrypt(data, key):
    data = mc.visEncry(data)
    aes = AES.new(key, AES.MODE_ECB)
    data = aes.encrypt(aes_pad(data))
    return data

def unpack(data, verb, key):
    if key is not None:
        data = aes_decrypt(data, key)

    data = t.unpack(data, verb, chtstruct)

    result = []
    items = data["items"]

    for item in items:
        if item.id == item._cfgids['CFGID_OUTER_PAYLOAD'] and not item.data.startswith("MZ"):
            try:
                nested = unpack(item.data, verb, key)
                result += nested["items"]
            except ValueError:
                nested = unpack(item.data, verb, None)
                result += nested["items"]

        elif item.id == item._cfgids['CFGID_PAYLOAD'] and item.flags & item._flags['ITEMF_IS_PACKED_CONFIG']:
            nested = unpack(item.data, verb, None)
            result += nested["items"]
        elif item.id == item._cfgids['CFGID_INJECTS']:
            nested = unpack(item.data, verb, None)
            result += nested["items"]
        else:
            result.append(item)

    data['items'] = result

    return data

def pack(data, verb, aes_key):
    packet = zeus.pack(data, verb)
    packet = aes_encrypt(packet, aes_key)

    return packet

def parse(data, verb):
    ret =  t.parse(data, verb, cht)

    for i in data['items']:
        if i.data.startswith("MZ"):
            ret['PE'] = i.data
    return ret


def to_str(data, verb):
    if not isinstance(data, dict):
        verb('I need unpacked data')
        return

    fmt = zeusfmt.fmt(data)
    fmt._ = 'Cthonic'
    return fmt.format()

def format(data, verb, type='pretty'):
    if type == 'pretty':
        return to_str(data, verb)
    elif type == 'json':
        return json.dumps(data)

def go(data, verb, aeskey):
    if not data:
        return ""
    if len(data) % 16 != 0:
        return ""

    data = unpack(data, verb, aeskey)
    data = parse(data, verb)
    return data

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
        st['aes-key'] = self.aeskey
        del st['rc4sbox']
        return st

    def set_aes(self, aeskey):
        self.aeskey = aeskey

def parse_basecfg(basecfg, _args):
   cfg  = ChthonicCfg(basecfg)
   cfg.set_aes(_args['aes-key'])
   return cfg.get_basics()
