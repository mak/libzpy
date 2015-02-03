from libs.structure import DataStructure,StructList
from libs.structure import c_dword,c_byte
import structs.zeus as zeus


class Header(DataStructure):
    _have_data=False
    _fields_ = [ ('junk',c_byte*32), ('size',c_dword), ('flags',c_dword), ('count',c_dword),('md5',c_byte*4)]

class Item(zeus.Item):
    pass

