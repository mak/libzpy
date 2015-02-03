import structs.zeus as z


def pesettings(data,verb):
    p = z.PESettings(data)
    p._sep = "\n"
    print str(p)

def pesettings_key(data,verb):
    p = z.PESettings(data)
    p._sep = "\n"
    print p.RC4KEY
