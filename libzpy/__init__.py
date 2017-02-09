import sys,os
#from contextlib import contextmanager

def get_mydir():
    p = os.path.abspath(__file__)
    dir_path = os.path.dirname(p)
    return dir_path

#@contextmanager
def get_parser(m):

    mod = __import__('.'.join(['libzpy.modules',m]))
    return getattr(mod.modules,m)

def show_version(v):
    return "%02d.%02d.%02d.%02d"%(v>>24,(v>>16)&0xff,(v>>8)&0xff,v&0xff)
