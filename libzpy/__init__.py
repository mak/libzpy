import sys,os

def get_mydir():
    p = os.path.abspath(__file__)
    dir_path = os.path.dirname(p)
    return dir_path

def get_parser(m):

    d = get_mydir()
    if d not in sys.path:
        sys.path = [d] + sys.path
        while '/home/mak/tools/mtracker' in sys.path:
            sys.path.remove('/home/mak/tools/mtracker')

    if 'libs' in sys.modules:
        del sys.modules['libs']

    if 'modules' in sys.modules:
        del sys.modules['modules']

    return getattr(__import__('.'.join(['modules',m])),m)


