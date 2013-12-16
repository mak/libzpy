import binascii



def s2hex(s): return binascii.hexlify(s)

def hex2s(s): return binascii.unhexlify(s)



