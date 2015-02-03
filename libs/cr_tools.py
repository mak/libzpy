#!/usr/bin/env python2
from Crypto.Cipher import AES
from Crypto.Cipher import ARC4
import argparse,sys,struct

aparse = argparse.ArgumentParser(description='RC4  decoder')
aparse.add_argument('-f','--file')
aparse.add_argument('-k','--key')
aparse.add_argument('-d','--data')
aparse.add_argument('-v','--visual',action='store_true')
aparse.add_argument('-vv','--vvisual',action='store_true')
aparse.add_argument('-t','--type',help='Type of encryptionk key: bin/string/hex')
aparse.add_argument('-6',action='store_true',default=False,dest='v6')

  
class RC6(object):
    def __init__(self, key):
        self.state = S = []
        key += "\0" * (4 - len(key) & 3) # pad key
  
        L = list(struct.unpack("<%sL" % (len(key) / 4), key))
  
        S.append(0xb7e15163)
        for i in range(43):
            S.append(_add(S[i], 0x9e3779b9))
  
        v = max(132, len(L) * 3)
  
        A = B = i = j = 0
  
        for n in range(v):
            A = S[i] = _rol(_add(S[i], A, B), 3)
            B = L[j] = _rol(_add(L[j] + A + B), _add(A + B))
            i = (i + 1) % len(S)
            j = (j + 1) % len(L)
  
    def encrypt(self, block):
        S = self.state
        A, B, C, D = struct.unpack("<4L", block.ljust(16, '\0'))
  
        B = _add(B, S[0])
        D = _add(D, S[1])
  
        for i in range(1, 21): # 1..20
            t = _rol(_mul(B, _rol(B, 1) | 1), 5)
            u = _rol(_mul(D, _rol(D, 1) | 1), 5)
            A = _add(_rol(A ^ t, u), S[2 * i])
            C = _add(_rol(C ^ u, t), S[2 * i + 1])
  
            A, B, C, D = B, C, D, A
  
        A = _add(A, S[42])
        C = _add(C, S[43])
  
        return struct.pack("<4L", A, B, C, D)
  
    def decrypt(self, block,state = None):
        S = state if state else self.state 
        A, B, C, D = struct.unpack("<4L", block.ljust(16,"\0"))# * 16)
  
        C = _add(C, -S[43])
        A = _add(A, -S[42])
  
        for i in range(20,0,-1): # 20..1
            A, B, C, D = D, A, B, C
  
            u = _rol(_mul(D, _add(_rol(D, 1) | 1)), 5)
            t = _rol(_mul(B, _add(_rol(B, 1) | 1)), 5)
            C = _ror(_add(C, -S[2 * i + 1]), t) ^ u
            A = _ror(_add(A, -S[2 * i]), u) ^ t
  
        D = _add(D, -S[1])
        B = _add(B, -S[0])
  
        return struct.pack("<4L", A&0xffffffff, B&0xffffffff, C&0xffffffff, D&0xffffffff)#[A,B,C,D] 
  
# helper functions for rc6
  
def _add(*args):
    return sum(args) % 4294967296
  
def _rol(x, n):
    n = 31 & n
    return x << n | 2 ** n - 1 & x >> 32 - n
  
def _ror(x, y): # rorororor
    return _rol(x, 32 - (31 & y))
  
def _mul(a, b):
    return (((a >> 16) * (b & 65535) + (b >> 16) * (a & 65535)) * 65536 +
            (a & 65535) * (b & 65535)) % 4294967296

def rc6decrypt(d,k):
#    if args.type == 'str':
#        rc = RC6(k)
#        ciph = lambda d,k: rc.decrypt(d)
#    else:
    if type(k) == str:
        k = struct.unpack('I'*(len(k)/4),k)
    ciph = lambda d,k:RC6('a'*16).decrypt(d,k)
    r = ''
    for i in range(0,len(d)>>4):
        r+=ciph(d[i*16:(i+1)*16],k)
    return r


def aesdecrypt(d,k,xor):
    clean = AES.new(k,AES.MODE_ECB).decrypt(d)
    if xor:
        xor = map(ord,xor)
        lxor = len(xor)
        r = ''
        for i in xrange(0,len(clean),lxor):
            r += ''.join(map(lambda x: chr(ord(x[0])^x[1]),zip(clean[i:i+lxor],xor)))
        clean = r
    return clean


#def rc4init(key,
 
def rc4decrypt(data, key,xor=None,mod1=0,mod2=0,raw=False):

    if raw:
        cip = ARC4.new(key)
        return cip.decrypt(data)

    box = map(ord,key)
    x = 0
    y = 0
    out = []
    idx =0
    for byt in data:
        x = (x + 1 + mod1 ) % 256
        y = (y + box[x] + mod2) % 256
        box[x], box[y] = box[y], box[x]
        byt = ord(byt) ^ box[(box[x] + box[y]) % 256]
        if xor:
          byt ^= ord(xor[idx%len(xor)])  
          idx+=1
        out.append(chr(byt))
    
    return ''.join(out)

def visEncry(datA):
    i = len(datA)-1
    ret =map(ord,(datA))
    for idx in range(1,len(datA)):
        ret[idx] ^= ret[idx-1]
    return ''.join(map(chr,ret))


def visDecry(datA):
    i = len(datA)-1
    ret =map(ord,(datA))
    for idx in range(len(datA)-1,0,-1):
        ret[idx] ^= ret[idx-1]
    return ''.join(map(chr,ret))

def ppr(d):
    if args.visual:
        sys.stdout.write(visDecry(d))
    else:
        sys.stdout.write( d)

def ciph(d,k):
    if args.v6:
        return rc6decrypt(d,k)
    else:
        return rc4decrypt(d,k)

if __name__ == '__main__':
    args = aparse.parse_args()    
    if args.type == 'bin':
        with open(args.key) as f: key = f.read()
    elif args.type == 'str':
        key = args.key
    elif args.type == 'hexstr':
        key = args.key.decode('hex')
    elif args.type == 'hex':
        with open(args.key) as f: key = f.read().replace(' ','').replace('\n','').replace('\r','').decode('hex')
    else:
        print "Unknown format"
        sys.exit(1)
#print `key`
#print len(key)
    if args.vvisual:
        key = visDecry(key)
        
    if args.file and args.file != '-':
        with open(args.file) as f:
            ppr(ciph(f.read(),key))
    elif args.file:
        ppr(ciph(sys.stdin.read(),key))
    else:
        ppr(ciph(args.data,key))
