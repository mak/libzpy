import structs.powerzeus as pz
from StringIO import StringIO

def unpack(data,verb):
    data=  StringIO(data)
    stor = pz.Header(data)
    print `stor.rand`
    print `stor.size`
    print `stor.count`
    print `stor.md5`
    print stor._str_field(('md5',stor.md5))
    for idx in range(stor.count):
        itm = pz.Item(data)
        print str(itm)
