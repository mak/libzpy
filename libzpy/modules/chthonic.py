from Crypto.Cipher import AES
import libzpy.structs.chthonic as cht
import libzpy.fmt.zeus as zeusfmt
from libzpy.libs.basecfg import BaseCfg
from libzpy.libs.vmzeus import VmContext as VM
from libzpy.modules import template as t
from mlib import memory
import json
import re
import sys
import StringIO
import hashlib
import struct
import os
import libzpy.structs.chthonic as zeus


AES_BLOCK_SIZE = 16

def p32(s):
    return struct.pack('<I', s)

def aes_pad(s):
    return s + (AES_BLOCK_SIZE - len(s) % AES_BLOCK_SIZE) * chr(AES_BLOCK_SIZE - len(s) % AES_BLOCK_SIZE)

def aes_decrypt(data, key):
    aes = AES.new(key, AES.MODE_ECB)
    data = aes.decrypt(data)
    return '\x00' + ''.join(chr(ord(x0) ^ ord(x1)) for x0, x1 in zip(data[1:], data[:-1]))

def aes_encrypt(data, key):
   
    tmp = ""
    z = 0
    for i in [ord(x) for x in "\x00"+data]:
        z ^= i
        tmp += chr(z)
    data = tmp

    aes = AES.new(key, AES.MODE_ECB)
    data = aes.encrypt(aes_pad(data))

    return data

def unpack(data, verb, key):
    if key is not None:
        data = aes_decrypt(data, key)

    data = t.unpack(data, verb, zeus)

    result = []
    items = data["items"]

    for item in items:
        
        if item.id == 12003 and not item.data.startswith("MZ"):
            nested = unpack(item.data, verb, key)
            result += nested["items"]
        elif item.id == 12000:
            nested = unpack(item.data, verb, None)
            result += nested["items"]
        elif item.id == 2541227442:
            nested = unpack(item.data, verb, None)
            result += nested["items"]
        else:
            result.append(item)
    data['items'] = result
    return data

def pack(data, aes_key, encrypt=True):
    chunks = ""

    for c in data["chunks"]:
        chunks += pack_chunk(c)

    packet_size = 48 + len(chunks)
    flags = data["flags"]
    chunks_no = len(data["chunks"])

    packet = os.urandom(19)
    packet += p32(packet_size)
    packet += p32(flags)
    packet += p32(chunks_no)
    packet += hashlib.md5(chunks).digest()
    packet += chunks

    packet = aes_encrypt(packet, aes_key)

    return packet

def pack_chunk(data):

    chunk_type = data["type"]
    flags = data["flags"]
    uncompressed_data = data["payload"]

    if flags & 1:
        compressed_data = UCL().compress(uncompressed_data)
    else:
        compressed_data = uncompressed_data

    compressed_size = len(compressed_data)
    uncompressed_size = len(uncompressed_data)

    chunk  = p32(chunk_type)
    chunk += p32(flags)
    chunk += p32(compressed_size)
    chunk += p32(uncompressed_size)
    chunk += compressed_data

    return chunk

def parse(data, verb):
    return t.parse(data, verb, cht)


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

###

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
