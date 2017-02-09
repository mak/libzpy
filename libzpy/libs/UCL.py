from ctypes import *
import os
from mlib.compression import lznt1 


class UCL(object):
    def decompress(self,data,size):
        return lznt1.decompress(data)
