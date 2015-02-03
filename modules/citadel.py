import libs.cr_tools as cry
import struct 
import structs.citadel as zeus
import fmt.citadel as cfmt
from  . import template as t
from libs.basecfg import BaseCfg

from StringIO import StringIO
from ctypes import sizeof
from hashlib import md5
import json


class CitaCfg(BaseCfg):
    def __init__(self,cfg,lk):
        self.lk  = lk
        self.cfg = cfg
        self.rc4sbox = None

    def rc4(self,d,k):
        return cry.rc4decrypt(d,k,self.lk)

    def get_rc4(self,off):
        self.rc4sbox = self.cfg[off:off+0x102]

def unpack(data,verb):
    return t.unpack(data,verb,zeus)

def parse(data,verb):
    data = t.parse(data,verb,zeus)
    print `data`
    for id in range(20009,20021) + range(20101,20204):
        if id in data and id == 20009:
            d = t.string_list(data[id])
            data['dns_filter'] =d 
            del data[id]

        elif id in data and id == 20010:
            d = t.string_list(data[id])
            data['cmds'] =d 
            del data[id]
        elif id in data and id == 20011:
            pass

        elif id in data and id == 20012:
            pass
        elif id in data and id == 20013:
            pass
        elif id in data and id == 20014:
            pass

        elif id in data and id == 20015:
            d = data[id].strip("\x00")
            data['keyloger'] = d
            del data[id]

        elif id in data and id == 20016:
            d = struct.unpack('I',data[id])[0]
            data['keyloger_time'] = d
            del data[id]

        elif id in data and id == 20017:
            pass

        elif id in data and id == 20018:
            d = data[id].strip("\x00")
            data['webinj_url'] = d
            del data[id]

        elif id in data and id == 20019:
            pass
            
        elif id in data and id == 20020:
            d = t.string_list(data[id])
            data['httpvip'] = d
            del data[id]

        elif id in data and id == 20101:

            d = struct.unpack('I',data[id])[0]
            data['video_length'] = d
            del data[id]

        elif id in data and id == 20102:
            d = struct.unpack('I',data[id])[0]
            data['video_qual' ] =d
            del data[id]

    return data


def to_str(data,verb):
    if not isinstance(data,dict):
        verb('I need unpacked data')
        return

    fmt = cfmt.fmt(data)
    fmt._name = 'Citadel'
    return fmt.format() + '\n\nUNKNOWN_DATA:\n\n' + '\n'.join(data.get('unknown',''))


def json(data):
    verb=lambda x:x
    data = unpack(data,verb)
    data = parse(data,verb)

    return data

        
def go(data,verb):
    data = unpack(data,verb)
    data = parse(data,verb)
    print to_str(data,verb)
    return to_str(data,verb)


def format(data,verb,type='pretty'):
    if type == 'pretty':
        return to_str(data,verb)
    elif type == 'json':
        return json.dumps(data)


def rc4_init_cit(key, magicKey):
    """ Initialize the RC4 keystate """
    
    hash = []
    box = []
    keyLength = len(key)
    if type(magicKey) == int:
        magicKey = pack('I',magicKey)
    magicKeyLen = len(magicKey)
    
    for i in range(0, 256):
        hash.append(ord(key[i % keyLength]))
        box.append(i)
        
    y = 0
    for i in range(0, 256):
        y = (y + box[i] + hash[i]) % 256
        tmp = box[i]
        box[i] = box[y]
        box[y] = tmp;

    y= 0
    for i in range(0, 256):
        magicKeyPart1 = ord(magicKey[y])  & 0x07;
        magicKeyPart2 = ord(magicKey[y]) >> 0x03;
        y += 1
        if (y == magicKeyLen):
            y = 0
            
        if (magicKeyPart1 == 0):
            box[i] = ~box[i]
        elif (magicKeyPart1 == 1):
            box[i] ^= magicKeyPart2
        elif (magicKeyPart1 == 2):
            box[i] += magicKeyPart2
        elif (magicKeyPart1 == 3):
            box[i] -= magicKeyPart2
        elif (magicKeyPart1 == 4):
            box[i] = box[i] >> (magicKeyPart2 % 8) | (box[i] << (8 - (magicKeyPart2 % 8)))
        elif (magicKeyPart1 == 5):
            box[i] = box[i] << (magicKeyPart2 % 8) | (box[i] >> (8 - (magicKeyPart2 % 8)))
        elif (magicKeyPart1 == 6):
            box[i] += 1
        elif (magicKeyPart1 == 7):
            box[i] -= 1
            
        box[i] = box[i]  & 0xff

    return ''.join([chr(c) for c in box])




def parse_basecfg(basecfg,args):
    login_key = args['lk']
    salt = args['s']
    off = args['off']
    bc = CitaCfg(basecfg,login_key)
    bc.get_rc4(off)
    st = bc.get_basics()
    aes = bc.rc4(md5(login_key).digest(),bc.rc4sbox)

    comm = rc4_init_cit(aes,salt)
    
    st['aes-key'] = aes.encode('hex')
    st['rc4cfg'] = bc.rc4sbox.encode('hex')
    st['rc4sbox'] = (comm+"\x00\x00").encode('hex') 
    st['login_key'] = login_key
    st['cfg'] = st['urls'][0]
    if 'aes_xor' in args:
        st['aes_xor'] = args['aes_xor']
                
    return st


## we allready decode basecfg
def get_basecfg(d,*args):
    return d.decode('hex')
