import structs.zeus as z


def pesettings(data,verb,type):
    p = z.PESettings(data)
    p._sep = "\n"
    print str(p)
    return p

def get_pesettings_size(type,verb):
    return 0x1e6

def pesettings_key(data,verb):
    p = z.PESettings(data)
    p._sep = "\n"
    print p.RC4KEY
