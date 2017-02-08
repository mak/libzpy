from ctypes import *
import os
from mlib.compression.lznt1 import decompress_data


class UCL(object):
    def decompress(self,data,size):
        return decompress_data(data)
