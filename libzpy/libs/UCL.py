from ctypes import *
import os


class UCL(object):

    def __init__(self):
        MYSELF = os.path.abspath(os.path.expanduser(__file__))
        if os.path.islink(MYSELF):
            MYSELF = os.readlink(MYSELF)
        DIR = os.path.dirname(MYSELF)
        if sizeof(c_long) == 8:
            UCL = DIR + '/libucl_x64.so'
        else:
            UCL = DIR + '/libucl_i386.so'
        self._lib = cdll.LoadLibrary(UCL)

    def decompress(self,data,size):
        compressed = c_buffer(data)
        decompressed = c_buffer(size)
        decompressed_size = c_int()
        result = self._lib.ucl_nrv2b_decompress_le32(
            pointer(compressed),
            c_int(len(compressed.raw)),
            pointer(decompressed),
            pointer(decompressed_size))
        return decompressed.raw[:decompressed_size.value]
