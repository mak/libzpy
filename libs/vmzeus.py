
#!/usr/bin/python
########################################################################
# Copyright (c) 2014
# all other co-authors here :)
# Daniel Plohmann <daniel.plohmann<at>gmail<dot>com>
# All rights reserved.
########################################################################
#
#  This is free software: you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see
#  <http://www.gnu.org/licenses/>.
#
########################################################################

import struct
import Crypto.Cipher.ARC4

# Hexdump
# courtesy of http://code.activestate.com/recipes/142812/
FILTER = "".join([(len(repr(chr(x))) == 3) and chr(x) or "." for x in range(256)])


def hexdump(src, length=16):
    N = 0
    result = ""
    while src:
        s, src = src[:length], src[length:]
        hexa = " ".join(["%02X" % ord(ch) for ch in s])
        s = s.translate(FILTER)
        result += "%04X   %-*s   %s\r\n" % (N, length * 3, hexa, s)
        N += length
    return result


class VmContext(object):

    def __init__(self, bytecode, config):
        self.bytecode = bytecode
        self.config = config
        self.eip = 0
        self.edi = 0
        self.ecx = 0
        self.r = [0 for i in xrange(16)]
        self.magics = {"nop": {1: 0x32, 2: 0x26, 4: 0xF3},
                       "xor": {1: 0xF1, 2: 0xE9, 4: 0x6A},
                       "add": {1: 0x73, 2: 0xD9},
                       "sub": {1: 0xEB},
                       "rol": {1: 0x85},
                       "ror": {1: 0xF3, 2: 0xA6},
                       "not": {1: 0xE7, 2: 0x8B, 4: 0x24},
                       "reorder": 0xBA,
                       "rc4": 0xE9,
                       "setecx": {2: 0xDA, 4: 0x70},
                       "setedi": 0xC8,
                       "loop": {1: 0xD0, 2: 0xEC},
                       "mov_r_const": {1: 0x0B, 2: 0x0F, 4: 0x70},
                       "mov_r_r": {1: 0x46, 2: 0x39, 4: 0x9E},
                       "add_r_r": {1: 0x72, 2: 0x5F, 4: 0xF9},
                       "sub_r_r": {1: 0x1E, 2: 0xD1, 4: 0xA6},
                       "xor_r_r": {1: 0xDB, 2: 0xAC, 4: 0xB7},
                       "add_r_const": {1: 0x9D, 2: 0x8f, 4: 0x28},
                       "sub_r_const": {1: 0x52, 2: 0x85, 4: 0xD8},
                       "xor_r_const": {1: 0xD5, 2: 0x24, 4: 0x2E},
                       "stos_add": {1: 0x65, 2: 0x89, 4: 0xDC},
                       "stos_sub": {1: 0x1D, 4: 0xA0},
                       "stos_xor": {1: 0x41, 2: 0x46, 4: 0x29},
                       "lods": {1: 0xB8, 2: 0x68, 4: 0xFD},
                       "stos": {1: 0x16, 2: 0xBB, 4: 0xF0}
        }
        self.instr_table = [self.instr_nop_byte, self.instr_nop_word, self.instr_nop_dword,
                            self.instr_xor_byte, self.instr_xor_word, self.instr_xor_dword,
                            self.instr_add_byte, self.instr_add_word, self.instr_add_dword,
                            self.instr_sub_byte, self.instr_sub_word, self.instr_sub_dword,
                            self.instr_rol_byte, self.instr_rol_word, self.instr_rol_dword,
                            self.instr_ror_byte, self.instr_ror_word, self.instr_ror_dword,
                            self.instr_not_byte, self.instr_not_word, self.instr_not_dword,
                            self.instr_reorder,
                            self.instr_rc4,
                            self.instr_setecx_byte, self.instr_setecx_word, self.instr_setecx_dword,
                            self.instr_setedi,
                            self.instr_loop_byte, self.instr_loop_word,
                            self.instr_mov_r_const_byte, self.instr_mov_r_const_word, self.instr_mov_r_const_dword,
                            self.instr_mov_r_r_byte, self.instr_mov_r_r_word, self.instr_mov_r_r_dword,
                            self.instr_add_r_r_byte, self.instr_add_r_r_word, self.instr_add_r_r_dword,
                            self.instr_sub_r_r_byte, self.instr_sub_r_r_word, self.instr_sub_r_r_dword,
                            self.instr_xor_r_r_byte, self.instr_xor_r_r_word, self.instr_xor_r_r_dword,
                            self.instr_add_r_const_byte, self.instr_add_r_const_word, self.instr_add_r_const_dword,
                            self.instr_sub_r_const_byte, self.instr_sub_r_const_word, self.instr_sub_r_const_dword,
                            self.instr_xor_r_const_byte, self.instr_xor_r_const_word, self.instr_xor_r_const_dword,
                            self.instr_stos_add_byte, self.instr_stos_add_word, self.instr_stos_add_dword,
                            self.instr_stos_sub_byte, self.instr_stos_sub_word, self.instr_stos_sub_dword,
                            self.instr_stos_xor_byte, self.instr_stos_xor_word, self.instr_stos_xor_dword,
                            self.instr_lods_byte, self.instr_lods_word, self.instr_lods_dword,
                            self.instr_stos_byte, self.instr_stos_word, self.instr_stos_dword,
                            self.instr_leave
                           ]
        self.pack_sizes = {1: "B", 2: "H", 4: "I"}
        self.modulus = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF}

    def __str__(self):
        return "EIP: 0x%08x -> 0x%x | EDI: 0x%08x | ECX: 0x%08x" % (self.eip, ord(self.bytecode[self.eip]), self.edi, self.ecx)

    def _fix_xors(self,xors):
        suf = {'byte':1,'word':2,'dword':4}
        print 'Instrs: %d' % len(self.instr_table)
	print 'Magics %d' % len(xors)

        for idx in xrange(0,len(self.instr_table)-1):
            name = self.instr_table[idx].im_func.func_name.split('_')
            print 'Updating %s with %x' % (`name`,xors[idx])
            try:
                self.magics['_'.join(name[1:-1])][suf[name[-1]]] = xors[idx]
            except IndexError:
                self.magics[name[1]] = xors[idx]

            except KeyError:
                self.magics[name[1]] = xors[idx]


    def dump_r(self):
        output = "  Custom Registers: \n"
        for i in xrange(4):
            line = "   "
            for j in xrange(4):
                line += "%s  " % struct.pack("I", self.r[4 * i + j]).encode("hex")
            output += line + "\n"
        return output

    def run(self):
        self.instr_count = 0
        print "Decoding BaseConfig. Initial VM state:"
        print str(self) + "\n"
        stop_exec = False
        while not stop_exec and self.eip < len(self.bytecode):
            self.instr_count += 1	    
            print "+ fetching opcode [%d]: 0x%02x (%d)" % (self.instr_count, ord(self.bytecode[self.eip]), ord(self.bytecode[self.eip]))
            stop_exec = self.instr_table[ord(self.bytecode[self.eip])]()
            print "  ", str(self)

################################
# opcode handlers
################################
    def instr_nop_byte(self):
        # operand: 0x00
        self.instr_nop(1)

    def instr_nop_word(self):
        # operand: 0x01
        self.instr_nop(2)

    def instr_nop_dword(self):
        # operand: 0x02
        self.instr_nop(4)

    def instr_nop(self, size):
        eip_offset = {1: 0, 2: 1, 4: 1}[size]
        bXorKey = self.deref_bytecode(self.eip + eip_offset, 1) ^ self.magics["nop"][size]
        self.eip += size
        if self.deref_bytecode(self.eip, 1) & 0x80:
            self.decode_next_opcode_byte(bXorKey)
        print "  -> nop_%d" % (size)

    def instr_xor_byte(self):
        # operand: 0x03
        self.instr_xor(1)

    def instr_xor_word(self):
        # operand: 0x04
        self.instr_xor(2)

    def instr_xor_dword(self):
        # operand: 0x05
        self.instr_xor(4)

    def instr_xor(self, size):
        bXorKey = self.deref_bytecode(self.eip + 1, 1) ^ self.magics["xor"][size]
        self.eip += 1
        # there is some EDI fuckup here not properly dereferenced?
        # also EIP offset has to be adjusted
        value = self.deref_bytecode(self.eip, size) ^ self.deref_config(self.edi, size)
        replacement = struct.pack(self.pack_sizes[size], value)
        self.config = self.replace_in_buffer(self.config, self.edi, replacement)
        self.eip += size
        self.edi += size
        if self.deref_bytecode(self.eip, 1) & 0x80:
            self.decode_next_opcode_byte(bXorKey)
        print "  -> xor_%d 0x%08x" % (size, self.edi - size)

    def instr_add_byte(self):
        # operand: 0x09
        self.instr_add(1)

    def instr_add_word(self):
        # operand: 0x0a
        self.instr_add(2)

    def instr_add_dword(self):
        # operand: 0x0b
        self.instr_add(4)

    def instr_add(self, size):
        bXorKey = self.deref_bytecode(self.eip + 1, 1) ^ self.magics["add"][size]
        self.eip += 1
        value = self.deref_config(self.edi, size) + self.deref_bytecode(self.eip, size)
        replacement = struct.pack(self.pack_sizes[size], value & self.modulus[size])
        self.config = self.replace_in_buffer(self.config, self.edi, replacement)
        self.eip += size
        self.edi += size
        if self.deref_bytecode(self.eip, 1) & 0x80:
            self.decode_next_opcode_byte(bXorKey)
        print "  -> sub_%d 0x%08x" % (size, self.edi - size)

    def instr_sub_byte(self):
        # operand: 0x09
        self.instr_sub(1)

    def instr_sub_word(self):
        # operand: 0x0a
        self.instr_sub(2)

    def instr_sub_dword(self):
        # operand: 0x0b
        self.instr_sub(4)

    def instr_sub(self, size):
        bXorKey = self.deref_bytecode(self.eip + 1, 1) ^ self.magics["sub"][size]
        self.eip += 1
        value = self.deref_config(self.edi, size) - self.deref_bytecode(self.eip, size)
        replacement = struct.pack(self.pack_sizes[size], value & self.modulus[size])
        self.config = self.replace_in_buffer(self.config, self.edi, replacement)
        self.eip += size
        self.edi += size
        if self.deref_bytecode(self.eip, 1) & 0x80:
            self.decode_next_opcode_byte(bXorKey)
        print "  -> sub_%d 0x%08x" % (size, self.edi - size)

    def rol(self, buf, size, count):
        while count > 0:
            buf = (buf << 1 | buf >> (size * 8 - 1)) & self.modulus[size]
            count -= 1
        return buf

    def instr_rol_byte(self):
        # operand: 0x0c
        self.instr_rol(1)

    def instr_rol_word(self):
        # operand: 0x0d
        self.instr_rol(2)

    def instr_rol_dword(self):
        # operand: 0x0e
        self.instr_rol(4)

    def instr_rol(self, size):
        bXorKey = self.deref_bytecode(self.eip + 1, 1) ^ self.magics["rol"][size]
        count = self.deref_bytecode(self.eip + 1, size) & (size * 8 - 1)
        self.eip += 2
        dataOffset = self.edi
        replacement = struct.pack(self.pack_sizes[size], (self.rol(self.deref_config(dataOffset, size), size, count)) & self.modulus[size])
        self.config = self.replace_in_buffer(self.config, dataOffset, replacement)
        self.edi += size
        if self.deref_bytecode(self.eip, 1) & 0x80:
            self.decode_next_opcode_byte(bXorKey)
        print "  -> rol_%d 0x%08x" % (size, dataOffset)

    def ror(self, buf, size, count):
        while count > 0:
            buf = (buf >> 1 | buf << (size * 8 - 1)) & self.modulus[size]
            count -= 1
        return buf

    def instr_ror_byte(self):
        # operand: 0x0f
        self.instr_ror(1)

    def instr_ror_word(self):
        # operand: 0x10
        self.instr_ror(2)

    def instr_ror_dword(self):
        # operand: 0x11
        self.instr_ror(4)

    def instr_ror(self, size):
        bXorKey = self.deref_bytecode(self.eip + 1, 1) ^ self.magics["ror"][size]
        count = self.deref_bytecode(self.eip + 1, size) & (size * 8 - 1)
        self.eip += 2
        dataOffset = self.edi
        ### print "before: ", struct.pack(self.pack_sizes[size], self.deref_config(dataOffset, size)).encode("hex")
        replacement = struct.pack(self.pack_sizes[size], (self.ror(self.deref_config(dataOffset, size), size, count)) & self.modulus[size])
        ### print "after:  ", replacement.encode("hex")
        self.config = self.replace_in_buffer(self.config, dataOffset, replacement)
        self.edi += size
        if self.deref_bytecode(self.eip, 1) & 0x80:
            self.decode_next_opcode_byte(bXorKey)
        print "  -> ror_%d 0x%08x" % (size, dataOffset)

    def instr_not_byte(self):
        # operand: 0x12
        self.instr_not(1)

    def instr_not_word(self):
        # operand: 0x13
        self.instr_not(2)

    def instr_not_dword(self):
        # operand: 0x14
        self.instr_not(4)

    def instr_not(self, size):
        bXorKey = self.deref_bytecode(self.eip, 1) ^ self.magics["not"][size]
        self.eip += 1
        valueOffset = self.edi
        replacement = struct.pack(self.pack_sizes[size], (~self.deref_config(valueOffset, size)) & self.modulus[size])
        self.config = self.replace_in_buffer(self.config, valueOffset, replacement)
        self.edi += size
        if self.deref_bytecode(self.eip, 1) & 0x80:
            self.decode_next_opcode_byte(bXorKey)
        print "  -> not_%d 0x%08x" % (size, valueOffset)

    def instr_reorder(self):
        bXorKey = self.deref_bytecode(self.eip + 1, 1) ^ self.magics["reorder"]
        operand = self.deref_bytecode(self.eip + 1, 1)
        value = struct.pack(self.pack_sizes[4], self.deref_config(self.edi, 4))
        replacement = [0, 0, 0, 0]
        for i in xrange(4):
            index = operand & 0x3
            replacement[index] = value[i]
            operand = operand >> 2
        replacement = "".join(replacement)
        # after shuffling
        self.config = self.replace_in_buffer(self.config, self.edi, replacement)
        self.edi += 4
        self.eip += 2
        if self.deref_bytecode(self.eip, 1) & 0x80:
            self.decode_next_opcode_byte(bXorKey)
        print "  -> reorder 0x%08x" % (self.deref_config(self.edi - 4, 4))

    def instr_rc4(self):
        # operand: 0x16
        bXorKey = self.deref_bytecode(self.eip + 3, 1) ^ self.magics["rc4"]
        keySize = struct.unpack("B", self.bytecode[self.eip + 1])[0]
        dataSize = struct.unpack("B", self.bytecode[self.eip + 2])[0]
        # build rc4 key with password given in bytecode
        keyOffset = self.eip + 3
        rc4Key = self.bytecode[keyOffset:keyOffset + keySize]
        dataOffset = self.edi
        data = self.config[dataOffset:dataOffset + dataSize]
        rc4 = Crypto.Cipher.ARC4.new(rc4Key)
        cryptedBin = b"".join(data)
        plaintext = rc4.decrypt(cryptedBin)
        # insert decrypted part in config
        self.config = self.replace_in_buffer(self.config, self.edi, plaintext)
        self.edi += dataSize
        self.eip += 3 + keySize
        if self.deref_bytecode(self.eip, 1) & 0x80:
            self.decode_next_opcode_byte(bXorKey)
        print "  -> rc4 -> offset: 0x%08x (%d bytes), key_offset: 0x%08x (%d bytes)" % (dataOffset, dataSize, keyOffset, keySize)

    def instr_setecx_byte(self):
        # operand: 0x17
        self.instr_setecx(1)

    def instr_setecx_word(self):
        # operand: 0x18
        self.instr_setecx(2)

    def instr_setecx_dword(self):
        # operand: 0x19
        self.instr_setecx(4)

    def instr_setecx(self, size):
        bXorKey = self.deref_bytecode(self.eip + 1, 1) ^ self.magics["setecx"][size]
        self.eip += 1
        value = self.deref_bytecode(self.eip, size)
        self.ecx += value
        self.eip += size
        if self.deref_bytecode(self.eip, 1) & 0x80:
            self.decode_next_opcode_byte(bXorKey)
        print "  -> set_%d ecx, 0x%08x" % (size, value)

    def instr_setedi(self):
        # operand: 0x1A
        bXorKey = self.deref_bytecode(self.eip + 1, 1) ^ self.magics["setedi"]
        self.eip += 1
        self.edi += self.deref_bytecode(self.eip, 2)
        self.edi = self.edi & 0xFFFF
        self.eip += 2
        if self.deref_bytecode(self.eip, 1) & 0x80:
            self.decode_next_opcode_byte(bXorKey)
        print "  -> set edi, 0x%08x" % self.edi

    def instr_loop_byte(self):
        # operand: 0x1B
        self.instr_loop(1)

    def instr_loop_word(self):
        # operand: 0x1C
        self.instr_loop(2)

    def instr_loop(self, size):
        bXorKey = self.deref_bytecode(self.eip + 1, 1) ^ self.magics["loop"][size]
        if self.deref_bytecode(self.eip + 1 + size, 1) & 0x80:
            self.decode_next_opcode_byte(bXorKey, 1 + size)
        self.eip += 1
        if self.ecx != 0:
            self.ecx -= 1
            self.eip = self.eip + size - self.deref_bytecode(self.eip, size)
        else:
            self.eip += size
        print "  -> loop_%d 0x%08x" % (size, self.ecx)

    def instr_mov_r_const_byte(self):
        # operand: 0x1D
        self.instr_mov_r_const(1)

    def instr_mov_r_const_word(self):
        # operand: 0x1E
        self.instr_mov_r_const(2)

    def instr_mov_r_const_dword(self):
        # operand: 0x1F
        self.instr_mov_r_const(4)

    def instr_mov_r_const(self, size):
        bXorKey = self.deref_bytecode(self.eip + 2, 1) ^ self.magics["mov_r_const"][size]
        dst_r_index = self.deref_bytecode(self.eip + 1, 1) & 0xF
        value = self.deref_bytecode(self.eip + 2, 4) & self.modulus[size]
        self.r[dst_r_index] = value
        self.eip += 2 + size
        if self.deref_bytecode(self.eip, 1) & 0x80:
            self.decode_next_opcode_byte(bXorKey)
        print "  -> mov_%d r[%d], 0x%08x" % (size, dst_r_index, value)
        print self.dump_r()

    def instr_mov_r_r_byte(self):
        # operand: 0x20
        self.instr_mov_r_r(1)

    def instr_mov_r_r_word(self):
        # operand: 0x21
        self.instr_mov_r_r(2)

    def instr_mov_r_r_dword(self):
        # operand: 0x22
        self.instr_mov_r_r(4)

    def instr_mov_r_r(self, size):
        bXorKey = self.deref_bytecode(self.eip + 1, 1) ^ self.magics["mov_r_r"][size]
        dst_r_index = self.deref_bytecode(self.eip + 1, 1) & 0xF
        src_r_index = self.deref_bytecode(self.eip + 1, 1) >> 4
        # according to commentary: "lower than 32 bit size operations do not preserve destination's higher bits, they get set to 0"
        self.r[dst_r_index] = self.r[src_r_index] & self.modulus[size]
        self.eip += 2
        if self.deref_bytecode(self.eip, 1) & 0x80:
            self.decode_next_opcode_byte(bXorKey)
        print "  -> mov_%d r[%d], r[%d]" % (size, dst_r_index, src_r_index)
        print self.dump_r()

    def instr_add_r_r_byte(self):
        # operand: 0x23
        self.instr_add_r_r(1)

    def instr_add_r_r_word(self):
        # operand: 0x24
        self.instr_add_r_r(2)

    def instr_add_r_r_dword(self):
        # operand: 0x25
        self.instr_add_r_r(4)

    def instr_add_r_r(self, size):
        bXorKey = self.deref_bytecode(self.eip + 1, 1) ^ self.magics["add_r_r"][size]
        dst_r_index = self.deref_bytecode(self.eip + 1, 1) & 0xF
        src_r_index = self.deref_bytecode(self.eip + 1, 1) >> 4
        self.r[dst_r_index] += self.r[src_r_index] & self.modulus[size]
        self.r[dst_r_index] = self.r[dst_r_index] & self.modulus[4]
        self.eip += 2
        if self.deref_bytecode(self.eip, 1) & 0x80:
            self.decode_next_opcode_byte(bXorKey)
        print "  -> add_%d r[%d], r[%d]" % (size, dst_r_index, src_r_index)
        print self.dump_r()

    def instr_sub_r_r_byte(self):
        # operand: 0x26
        self.instr_sub_r_r(1)

    def instr_sub_r_r_word(self):
        # operand: 0x27
        self.instr_sub_r_r(2)

    def instr_sub_r_r_dword(self):
        # operand: 0x28
        self.instr_sub_r_r(4)

    def instr_sub_r_r(self, size):
        bXorKey = self.deref_bytecode(self.eip + 1, 1) ^ self.magics["sub_r_r"][size]
        dst_r_index = self.deref_bytecode(self.eip + 1, 1) & 0xF
        src_r_index = self.deref_bytecode(self.eip + 1, 1) >> 4
        self.r[dst_r_index] -= self.r[src_r_index] & self.modulus[size]
        self.r[dst_r_index] = self.r[dst_r_index] & self.modulus[4]
        self.eip += 2
        if self.deref_bytecode(self.eip, 1) & 0x80:
            self.decode_next_opcode_byte(bXorKey)
        print "  -> sub_%d r[%d], r[%d]" % (size, dst_r_index, src_r_index)
        print self.dump_r()

    def instr_xor_r_r_byte(self):
        # operand: 0x29
        self.instr_xor_r_r(1)

    def instr_xor_r_r_word(self):
        # operand: 0x2A
        self.instr_xor_r_r(2)

    def instr_xor_r_r_dword(self):
        # operand: 0x2B
        self.instr_xor_r_r(4)

    def instr_xor_r_r(self, size):
        bXorKey = self.deref_bytecode(self.eip + 1, 1) ^ self.magics["xor_r_r"][size]
        dst_r_index = self.deref_bytecode(self.eip + 1, 1) & 0xF
        src_r_index = self.deref_bytecode(self.eip + 1, 1) >> 4
        dst_value = self.r[dst_r_index] ^ (self.r[src_r_index] & self.modulus[size])
        self.r[dst_r_index] = dst_value
        self.eip += 2
        if self.deref_bytecode(self.eip, 1) & 0x80:
            self.decode_next_opcode_byte(bXorKey)
        print "  -> xor_%d r[%d], r[%d]" % (size, dst_r_index, src_r_index)
        print self.dump_r()

    def instr_add_r_const_byte(self):
        # operand: 0x2C
        self.instr_add_r_const(1)

    def instr_add_r_const_word(self):
        # operand: 0x2D
        self.instr_add_r_const(2)

    def instr_add_r_const_dword(self):
        # operand: 0x2E
        self.instr_add_r_const(4)

    def instr_add_r_const(self, size):
        bXorKey = self.deref_bytecode(self.eip + 2, 1) ^ self.magics["add_r_const"][size]
        dst_r_index = self.deref_bytecode(self.eip + 1, 1) & 0xF
        value = self.deref_bytecode(self.eip + 2, size)
        self.r[dst_r_index] += value
        self.r[dst_r_index] = self.r[dst_r_index] & self.modulus[4]
        self.eip += 2 + size
        if self.deref_bytecode(self.eip, 1) & 0x80:
            self.decode_next_opcode_byte(bXorKey)
        print "  -> add_%d r[%d], 0x%x" % (size, dst_r_index, value)
        print self.dump_r()

    def instr_sub_r_const_byte(self):
        # operand: 0x2F
        self.instr_sub_r_const(1)

    def instr_sub_r_const_word(self):
        # operand: 0x30
        self.instr_sub_r_const(2)

    def instr_sub_r_const_dword(self):
        # operand: 0x31
        self.instr_sub_r_const(4)

    def instr_sub_r_const(self, size):
        bXorKey = self.deref_bytecode(self.eip + 2, 1) ^ self.magics["sub_r_const"][size]
        dst_r_index = self.deref_bytecode(self.eip + 1, 1) & 0xF
        value = self.deref_bytecode(self.eip + 2, size)
        self.r[dst_r_index] -= value
        self.r[dst_r_index] = self.r[dst_r_index] & self.modulus[4]
        self.eip += 2 + size
        if self.deref_bytecode(self.eip, 1) & 0x80:
            self.decode_next_opcode_byte(bXorKey)
        print "  -> sub_%d r[%d], 0x%x" % (size, dst_r_index, value)
        print self.dump_r()

    def instr_xor_r_const_byte(self):
        # operand: 0x32
        self.instr_xor_r_const(1)

    def instr_xor_r_const_word(self):
        # operand: 0x33
        self.instr_xor_r_const(2)

    def instr_xor_r_const_dword(self):
        # operand: 0x34
        self.instr_xor_r_const(4)

    def instr_xor_r_const(self, size):
        bXorKey = self.deref_bytecode(self.eip + 2, 1) ^ self.magics["xor_r_const"][size]
        dst_r_index = self.deref_bytecode(self.eip + 1, 1) & 0xF
        value = self.deref_bytecode(self.eip + 2, size)
        self.eip += 2 + size
        self.r[dst_r_index] ^= value
        if self.deref_bytecode(self.eip, 1) & 0x80:
            self.decode_next_opcode_byte(bXorKey)
        print "  -> xor_%d r[%d], 0x%x" % (size, dst_r_index, value)
        print self.dump_r()

    def instr_stos_add_byte(self):
        # operand: 0x35
        self.instr_stos_add(1)

    def instr_stos_add_word(self):
        # operand: 0x36
        self.instr_stos_add(2)

    def instr_stos_add_dword(self):
        # operand: 0x37
        self.instr_stos_add(4)

    def instr_stos_add(self, size):
        bXorKey = self.deref_bytecode(self.eip + 1, 1) ^ self.magics["stos_add"][size]
        src_r_index = self.deref_bytecode(self.eip + 1, 1) & 0xF
        self.eip += 2
        valueOffset = self.edi
        replacement = struct.pack(self.pack_sizes[size], (self.deref_config(valueOffset, size) + self.r[src_r_index]) & self.modulus[size])
        # print self.config[valueOffset:valueOffset + 4].encode("hex")
        self.config = self.replace_in_buffer(self.config, valueOffset, replacement)
        # print self.config[valueOffset:valueOffset + 4].encode("hex")
        self.edi += size
        if self.deref_bytecode(self.eip, 1) & 0x80:
            self.decode_next_opcode_byte(bXorKey)
        print "  -> add_%d stos edi, r[%d]" % (size, src_r_index)
        print self.dump_r()

    def instr_stos_sub_byte(self):
        # operand: 0x38
        self.instr_stos_sub(1)

    def instr_stos_sub_word(self):
        # operand: 0x39
        self.instr_stos_sub(2)

    def instr_stos_sub_dword(self):
        # operand: 0x3a
        self.instr_stos_sub(4)

    def instr_stos_sub(self, size):
        bXorKey = self.deref_bytecode(self.eip + 1, 1) ^ self.magics["stos_sub"][size]
        src_r_index = self.deref_bytecode(self.eip + 1, 1) & 0xF
        valueOffset = self.edi
        replacement = struct.pack(self.pack_sizes[size], (self.deref_config(valueOffset, size) - self.r[src_r_index]) & self.modulus[size])
        self.config = self.replace_in_buffer(self.config, valueOffset, replacement)
        self.eip += 2
        self.edi += size
        if self.deref_bytecode(self.eip, 1) & 0x80:
            self.decode_next_opcode_byte(bXorKey)
        print "  -> sub_%d stos edi, r[%d]" % (size, src_r_index)
        print self.dump_r()

    def instr_stos_xor_byte(self):
        # operand: 0x3b
        self.instr_stos_xor(1)

    def instr_stos_xor_word(self):
        # operand: 0x3c
        self.instr_stos_xor(2)

    def instr_stos_xor_dword(self):
        # operand: 0x3d
        self.instr_stos_xor(4)

    def instr_stos_xor(self, size):
        bXorKey = self.deref_bytecode(self.eip + 1, 1) ^ self.magics["stos_xor"][size]
        src_r_index = self.deref_bytecode(self.eip + 1, 1) & 0xF
        self.eip += 2
        valueOffset = self.edi
        replacement = struct.pack(self.pack_sizes[size], (self.deref_config(valueOffset, size) ^ self.r[src_r_index]) & self.modulus[size])
        self.config = self.replace_in_buffer(self.config, valueOffset, replacement)
        self.edi += size
        if self.deref_bytecode(self.eip, 1) & 0x80:
            self.decode_next_opcode_byte(bXorKey)
        print "  -> xor_%d stos edi, r[%d]" % (size, src_r_index)
        print self.dump_r()

    def instr_lods_byte(self):
        # operand: 0x3e
        self.instr_lods(1)

    def instr_lods_word(self):
        # operand: 0x3f
        self.instr_lods(2)

    def instr_lods_dword(self):
        # operand: 0x40
        self.instr_lods(4)

    def instr_lods(self, size):
        bXorKey = self.deref_bytecode(self.eip + 1, 1) ^ self.magics["lods"][size]
        dst_r_index = self.deref_bytecode(self.eip + 1, 1) & 0xF
        dst_value = self.r[dst_r_index] & (0xFFFFFFFF - self.modulus[size])
        dst_value += self.deref_config(self.edi, size)
        self.r[dst_r_index] = dst_value
        self.eip += 2
        if self.deref_bytecode(self.eip, 1) & 0x80:
            self.decode_next_opcode_byte(bXorKey)
        print "  -> lods_%d edi, r[%d]" % (size, dst_r_index)
        print self.dump_r()

    def instr_stos_byte(self):
        # operand: 0x41
        self.instr_stos(1)

    def instr_stos_word(self):
        # operand: 0x42
        self.instr_stos(2)

    def instr_stos_dword(self):
        # operand: 0x43
        self.instr_stos(4)

    def instr_stos(self, size):
        bXorKey = self.deref_bytecode(self.eip + 1, 1) ^ self.magics["stos"][size]
        src_r_index = self.deref_bytecode(self.eip + 1, 1) & 0xF
        replacement = struct.pack(self.pack_sizes[size], (self.r[src_r_index]) & self.modulus[size])
        self.config = self.replace_in_buffer(self.config, self.edi, replacement)
        self.eip += 2
        self.edi += size
        if self.deref_bytecode(self.eip, 1) & 0x80:
            self.decode_next_opcode_byte(bXorKey)
        print "  -> stos_%d edi, r[%d]" % (size, src_r_index)
        print self.dump_r()

    def instr_leave(self):
        return True

################################
# utility functions
################################

    def deref(self, buf, offset, size):
        return struct.unpack(self.pack_sizes[size], buf[offset:offset + size])[0]

    def deref_bytecode(self, offset, size):
        return self.deref(self.bytecode, offset, size)

    def deref_config(self, offset, size):
        return self.deref(self.config, offset, size)

    def decode_next_opcode_byte(self, key, offset=0):
        # decode the next opcode byte, depending on the XOR key of the function
        # in case of a loop function, the next opcode byte sits beyond an offset, thus the parameter
        self.bytecode = self.replace_in_buffer(self.bytecode,
                                               self.eip + offset,
                                               chr((self.deref_bytecode(self.eip + offset, 1) ^ key) & 0x7F)
                                              )

    def replace_in_buffer(self, buf, pos, bytes):
        if len(buf) <= pos:
            raise IndexError("buffer to short to replace at position")
        return buf[:pos] + \
               bytes + \
               buf[pos + len(bytes):]


if __name__ == "__main__":
    vm_bytecode = "1ac802960208e2e1916affb18705b70550deea058c2aa150fa055dad0e3ac005cdaad205d901ddcb081d8b060abd01cb9d8caa5e018cbefdee0100ce4bf53676c0035cbb75c4b20d4fbdf40d4ab25875c80d7dc9d3a50d1c4cbe0374c4cf0d95a523e888033d11ac0dd60ca9094af30c30d50ca44d910cce82fa0c131ff218fa09a5d9ba70c90ce84109b5e0c9fd99f40ca40bad00d894e7007ae5d5b0b900d0b0db004895e00000ddce0bdd04e7012860970167bdd604392c4894d404e293dba345271c1013cb2a7352273be735b5ecc487c7178e8263324f7d7161b9d4a87df22e0c9c81651d3c39e398db4af41aa59e6cfb8a5bb149ec940b92e5407d00e741131856d68862343e844e3f9c73ef9cc5831c2f4fffbec2ecbeeff3b2728451b1daaceb937906b8ef92e45e7b0f9fb662fd7d45720f11cac48644206661559f6ca5bdcd45af4bff1892920b6f588ae09b887cd61b01e1f01a1814bb4a958981152db53327ef6f41a89b6be426152e0998d0d1e1faab495818ad83b00ba821993f17b3f98e8d17ad7f37de4c04f2ff1ed5f892d1004ebea08b5788abb1132c97ad1a6cbce006bf5f06b43785d53cbbadb6eceef7633049fcd06414c83cf2448051490f0071a5f1f0c003929efa3082c8f5b9e723f543b69865703e733fee6f4b27cd0c7a914b648682426d591f49fc1db3326ae5874ba14310ba9c1de56a240ee6bc8c6b74b100b16693027296c0597b9628d7dec458dd1627b09f60e235d1b4189d9d67b48b47c07b0a78691dc34c12ad2324a03b6ce06fb3d9fbe74b81d4a11f35a624d0df6411acce0ef80906ccace9a40ebf1be842a50eb2a29f33a80ebe4e1338be0e054453238499e1e9b099830e9bcdba0e6e44b888ef99dd03f18f5123a493a80ea30f048a9049cfda245ab9e9915351a4df1edc08fe078008900d5934bd2d8a87d2dda687b503a50c990851f3b708a59741893950ba4d5e8fa0fb74e9ebccdbe46c48f86123e70802b4a3fc5a2d7f3771b7f90919dd5324763460366a3846626e37f8818a131e456eaac0d9fdf0784d482758909c5ffdca677e743552ad2f6456f3ecbceb3a5bc8bf91543b080c4d2b5da0f2ee34e4a97cfccf2921991e5dbcb841e978e78df70e3deb176990d4f527456d79db177c1f696b739d29811f397ef06556a978c4c62728a00dee0c93f8bfcc94ccd10d1004fe9dedcc93cce00ddfbb0c8d9c4383e10cf9c95693f90d2fac3e6dc40de009f6c90929b279ce990ac4d6f109bfd70524b201687042572daef4ad7d9ff44c38be40e011fac61ef8866c44e26548389e8b79ce0009f32fc85e3c44f8581599cad35915c8cd12d94ddbe732334cb8313796e44bed30ad7438773ed996a3aa612570da48725125c3573f8abac9685f836c8f7820c2fc1d593c79a26324df382afda4ee019d601e02c109b8f8e57dca8ef5af3d59f84fc4018c8fa659494803751a77234e6d37a1023464e4df299c3d56cfffabaeb71cf6e713b74d74967eb11bf49ff5d19e4ccb3e34cc0fe3cb17a84c7e2f5c7fc01e4a08cd20626059167f9e3d5dc2ec36fed990d711fec405869201460a971e8605333b9a013f8a55c005b7f9a0012f85a60521329f0500f3a8a6ea01a1c60104ec05b303239a3b8ace02a88d032e38e015a90290f3034c6c01018a0bb47f8a0bffe55bdf8b0349e00353703280e30ec5cefb038e424bdae60ef78fc1034b30c6b3c602bff7dbb0a70264b2c72e820b27d5ee8b025fe9a98dc903de05e5096ace058ff699b30143e0999b11fc05b9c0054ef091d105f0960586e5bd0ec27cd52d9d0e108105f440e29fbac90bfe077ee80458f4778f47b6b7bcb7cc44d80bfc2bd50b1eb20b3aa9a49ac977de003eea96b0cd04c3ea0bffa2bfd5930b8f03f5086f00cb38a303219a88bf38c5388a032b9b03efdfc88885888e03bacbc0faa003a8eedb850311870184910abd8f9933b50ac6d6d350b7a1d603329c0a3c24bf13e7aafc01b0fd099241ff8cc719d20a23c503f610e00193ec9a9809b552f1ebbaa1c209d8bd03daefe70388f73126fd8d93efefc0e984049bae33b7b18e5580898a36302451a3ac13a0c1f8c7837da666958eed920f0c5b341a540f916dd8e1bd00ca5a359ce477036ab0673c9571555316e33855d2e7e237aec35a2227c225ad56e697966b4166e4eef16a279dfbe838a499ca2bea35d2512ae006333f392e861df9470f7bb5b490c473a43a12b6fe3f46fdedb4f485fd8642367f6280794677c9cf8e205aafc78855d47928c06560e990b43c2b1a9101ece0b023f3b7bf1449de7da80e11ca0a03e270ad83c4e76269e568ef586b624e0e4d41a6a1ced08b8ec0a0fd47a0cff77add896322392f7f10f5d5781a38a3f4aea31ecd4a0c0b3b9af55273e8c9e4880ad2cfcd8d8aaab90af00fb8ad8bc1e1ff880f74c50fc4fdff8e0f10d5bec98c0f872e2e3e82ffd60e6c50d30e3f458e0e3c505801a50fc532dab182a9c63529f17e7ba2f0edb3a4ecdb7b0d86e80096ac06e4f3d1656b47a579660f1f788b2ba860fac75a97b1925938f1b2c01000d70ba0b507fde6d5bbf70408ae04a8ca8174de0b5af7531cdc4bcdb0da0067d40781d30de69904c95ae504ef0461e4d70457d3c0076e1fe604e7cb044fee140da6043095438dc607a1613e97ba00493ac204ec9100fa9e0499ae0a5567c70fae8a0a38c40f58983678ed0501b80517ee0a81b30558bb0f8b21b263f4ff8c5be1a5c80f37de0fcb346994ce548003f408db39a08f9808336cbd388b0b241089d0ff38a10306b86c288ab8f8009f5da78bc00321dab8cd0305c223689f0384f20bd13bb60b8f08b00bba0b916368199c30ef08be30b803b41301f8a8031a3acc0b840372c3b503b9e2cb0be3ecfc01e20ae01cde0138527a38d0015550cf07a9ba9273fdaac401f4f97fcc800139970180828117c8a79017e10779c3b501e3ef97fcc70300cda6e50a27dd10e211418fe7504f1353fc5cfb498b5917da8a85739ae391c8bbcfc21e8640efa9165cda326eccd26a71fc6b56c1e9b75d106f251b661e4b893fc48e41731c92bd33d9b1b0275cb5c494c5b49f65606c1ec20b930f0fac0dbb6b1541438928ad14abdf4c527e8fd70b4f08f62b7d829859f977fad3c8d492f4a90c2babd9054f96dc8aadc01df1436f92fd0e0e5104a29b8b64dfc86e0a31c7579a595cdf177078dcf282308d2cda5341acced0741ef4e4458dec56520b892272d8ca6e59f077a36382d248ed9ce8ddc1b23545adee0d8941f755aa93fb4dcdc431e0d27d600f3dfa2cf10ff90cad818c0ccb947adecc0fa6dffc890fa90191840466a2c60414f401ddb9048b58336bcd052f978615a1158e04d426b1ea08d1eb1013bc0f74cb0fce2475b8c988faffba0afa0dd188e3080586cae0850acd8c831cca0f0deb0ff954f4f6ffffe80f12edaa17e40fe34094edfb0f62fcc0afc60f97cc252cfcb094af05923432d7eaa724dc8d293ba46e205d0c1758c46d7e2939db6e677d3cf857574ee3deec824c50a8bd9783559957277ded905f4de7efb3332cc105144b67612236d7a767c24867c7e0e51da6a1beaa7b23b7e52b00659d1b8337e1ac5af08c3305038ba32d3b011a88581be90a7bd15703acb32c8d40824d3ba36cc50b539203cef55992f0100aafb380b5be30a3b2f56857e6e8f0ff01d306e4089bae2f50c2689c0621c7085aa2acb1d268d806ef7afe84f406d732df068bb588de68f406c805a00cc7d10ec8e7ee810ed63dfe05d759f40523a00727548507e0d6ca7ca905ac95cca00506238e07f0dc056e6eb5578205c8b99b61ce5ed6055a4946fcb305d302e105c588e60263d0025f78e35cd80213ee02d0ad02f98702b685020e90dd798a0206ab057301b502ec0df7dacb0d051c80d6dd0dd0acddab066446da06a68033dfcf0db867908cdc0dcad9f60af7f00574520665d659dd4877ea89e008cc6b389756be182dd3ec18ecca383a86bd3d5c60d07d3d2012feb441b40f3506be26a02be6e3aa03ee3e009b0d0f3f02a91cdf540bf0631a217080372d57e874f31ff82dabdbdc8e403047a53302b71859a5da702681ecf8640d03d9423a88a1ed9d4a33ea9f15d0dd772442bf13f2c751969f37ec8e41bc1cb1067d052dc9c1af3914e661906cdbc15c754002d6bbb94c18a0c0de86d60a9e11bbdb9db2f6e71e83df4a42e9de4bbcaa1d7927a65a0453a6fd9a595845b4a5f2f2722e28c8e87add9d24913c70eaf32e7e80484f5e90e8cce40a4d841ca0caef9e87cc41b18de5b8c68753fe9bb04e14aeadfcd935dc0100cbabb303a50d33348f0322e8b70305c226169c038b02b67ea6079508384ed707f78f025ce8e207cee4d767b522cd0f12a907f25bd222ef0f2d295922a3fa9677ef0a4c619ea0d60258397922d07ac3f289f7e602a47e9b23ac1d60d43c5ef68080f02457cbc66037b299c018c31be4c3c401b37d6fa66093b231645fef7eb495fecbb95df0e9bb0f02251869ea7df0f6f89d9e2526ef1ee74dec60749d008e80ecba892197d16569e26b742f35a88f4e018f44553ef43dfc1b5f67439417a45a496d70f224c4991e4f0c6b3a2c0b9aeca31e214e11f4bb8f4caad90cffccbd35bb466aaf59eaa95606f555764b0c92b6091c3ef82a3a5ce4e7e6da7aaedaefeb63be0d0a15eb63a63bb84fb654907c7dd817ab62aefecc0337f0d3e6b785fae417b42a858e511e5c4c62f832e9700b9b858b48a56301a05d86ecde7914840ca8bd00f06dddc6f40098a906cde3007fdac502a0319b06d783892dc906200a8fccd200ed8a02d0a80cfc94dc0059a160fd00280c4e90c800dd0fef0d7dd80f8bae386684fd820fa178947bca0fe9a9ea5303710015070eee06b8e7135f668b2bc047f048b50ebeacf4191160ff761304c800fc988e22e0c3bc5d85edd450ddaebca114f3ae1ccb92cca1989178b33e7df815e6f1266ae899dd9e0041303f49b3f85bdac8713e7373c8672182ec503a99757ac962db0d9b10d26c5247c28efb6784067698a93cfbc1830837422c6639d750beccb1765b75f4dbaa0e8efa62a0c1dd23b2790723fae500c1deffbdd84f2fdf2e7aadebb7d29e6ea0eafcba0400d9e522b09e8d7315268106158ff1354db5916a524975ee1a2ebfb8729c2940b96fc6a8d7fbc1a3791c03c6acabab4ea13bdc8720a05a2d6a6df9a829079c3a7058746487e146ff789b0aa0945b8d877effe2785e6c246f7751ebae10854d67f5aced5b802ef47c0300751dab0de930dc72234c44b9f21420f7fef5d104ad958e040f8c08ca2ad80261d204870786aa960e92027411d00e68a20972d0078baf0e48cbe0e98c0e11b85aa18f0e039fb40784e1097668df07f2dc076f22ff075a492312c807dc0cd5f10cbcc00cb55039fe80079da50c4d00c607bddc077471eb0cdb9d9b221cb4ac7c7518c71e2a1ea1a0cade6bc6a6cd03bfa759545a82316666c03614748a2c47bfb2065d4b9c237e23c597ab4d2db7688c7b0b9d3f41fa552f83c15fabbf236326c55b43bd20f11e9b29028673f1b9cd3d1dcf682a1240b01ef60a36ba113f11960b37bdb5d99e443d7c12858cc8cbaddacacb409ff25619cf3874af1c35c98fcd1461f789d04acd6250cec13572011bb9465299ca0f44f9d2d78301f00fde587cbc8ffef30fd38b737fd20ee1ae01a888e1c808be30830e09f7e1f9080eee0e42b80fc0aa0ed308e80e318e0822b296adab8ef9eeb308bc0000".decode("hex")
    vm_cconfig = "b1a4d432c9e0d7a5a65376312a3aa31d5c0f3d12d85d908ceabaea8138bb66f3e52407d63fd7d46f4e963aaaf99f25c59eab5240802a3872831ff4e7d51b81e1cbf463821da018f084d4474a7bd1f84dcce99a19ecbf7db1815a8bb7a8463f9c404178cf5107951af6ac2af34babc325b9243602f5e6701fd6f3f3465943b69b63698c7c80a45a28d0e1e43a2f9d22fffbbaa8e7970b216b47684b596f748f4010b7406e9365593bd106526b856e4e36103dffee93c463955d9a1732d6b11f9a9bf3a6a8322add2c43c5b4877f991365ecb3a8b6030c4664df321141200ea86ac3caa7ea41359a7184593f9dc8ccc833a06e66099b4d2acd0667d67aee229689ef56382195287ef9ec2635db14b0a4f79daf8f9322885d9db02b81aa6cd8c87ed9f50a6dd2ae5f37e5770871c1f1100ab8604c3533be403594a7f2de364447740f04a4d0cae4ae448fd60bd3d70f5cffd894814f07b050784015f560c0ad26b518895cb5f5310cdb59698e091d98971d411c0c7c8a0002da388af2211b4c6e4e223dec842ab2589c1142d2fbe76fe1b26c25e1a82ccf9b57c96fe71bc772445376c7a774f4dcfcb33cef3272c19d5c2619633a8718c745e219d986ac5090b1d0af9a063f3e80de559938051f26c05d16ab68d5826bcf2149dcf48fcd800a8e4640b559bdda924a5ce620e22d2267183fcd8ceb12d8296ea8ee094e5dee20faa34bc230dbb0cda2860282e39b662f0e94c0a317f39f6a497d58e2f60c796951213512933db8fe31125f6b896c32acf2f514930a9f209ac562e2713abd5c20ec1b99b5963a1e76fcd0e3d4e35e3f895e50a41cda56ffcf349086d270bc0684733c34e1ad96edb1b76272105d083fd62383221bc496a4b410a104ee3e95d07fc85d78e2dcbb4b7cb71875bac53be4996168744bcec430ecd8b7eb9f359c233e836400711a4c0e8f0c818fde7fa2a9d75e40aa8e28199b419ccbdb29c31bc54a5557547667cea73b73ba4c799a791f9b80f59ac0109f6695360f7bf757c759d22035cb4ec11b5f262c71a029bd18d4e11f0e5c101f2b3afecf354eea7940931e13e9dbafbb4f4da37573456eec7115a8fe3887909987a05b6aa96de6b50ee0393d49e9ddae6f27f45e35a41a7b1d9214570532ab53688b672582ffe36c778bbd59bf9c83b22d32e5d198fac241ced87a8d6631a1a58a35c19b37d93e47fd9588e3e10bbccca06ffb6af744246a037f95b85a7371395f363074455ab362511136a1e5547cc84d782d24d9284f2befe59308008408e557fcf6034d72e6d430b4780ab7ac1e404d64c9de6f".decode("hex")
    vm_dconfig = "96c73597606994ee41517aa32abff61d376dadfad71f1f4c2e7b2b02b71bd5a42ee14844ad8a17b11586c8ed0a000a001359675049712e0a2fc852621a6a80e1c049ac3c56d85584f5d50a9d42662df14e68f765bb04bc8d214d6f7a696c6c612f352e322028636f6d70617469626c653b204d53494520372e303b2057696e646f7773204e5420362e313b20535631290092b671be8b7381f7e1b33d8ff5213429f110fe475cbc74b3ecd2211f9b33f308fcf536e0d0abc36bd5e7756adefddd7728093730ec339c97313179b9e40e3f8e2a2a5c21f5836bf0d632a750000a00a7f77b44dc700cdd70d8abbfc90c8dde5bc45dcaca2380df4e8c9dbb0e01000083056f0d9411d09e058849db973a39392d00190022812c884da02f9a04f8f134d1fbec799ff7687474703a2f2f6c696c6963383831326173732e696e2f736f6369756d2f0049364586a50e358d4b34be3ba533d4036fae1a4d81e95419e98c1fe63da3e0d230e8fa02624544447d95baf37dab721c4f95d2de9e210117eaa19b3ddaeca989d3a5d05bc9c0c8da554110da0847e004004a6030b8a117162447a626fedeb6b45bf42f588186aa95fcc20f407f1207f3fd1d80118dbb057e8901a86a5182ef9bef5e7fc3339fd3be9aa06e55d911cd63723f9a378695223aea6309d17ddf3c85b86a286286142a9c563082010a0282010100b472d4c02e470e8031b5c604d10baa4c514f35ecb0b2b52abe6a3f36d4330f00201afc78b0077b7cbd87d1764e1c037c12be03ef01c99eac7b076f5c12f630001a88164409e6b45bfe07e23405c352dd31c4456b7ce97f1802bd9833b60dca07842598fc6c9b2b03916bde63e66d8c0fcc8659278fbc8a0178500feba3abf5c76bdbd89b0706f6303490363516cf2ee186734f962ece36aac5f8e67b1cce634ef740a2a95c360ec3dd94b78076a3b9865520ee096b11a039cac7ee4a5efd7cf17034cfe64224c4ad0329294e77b8d66d4a4839e8f0031ffa2e5124751e14bfe75371befc20f2adc378e737702a0995f9977c12e4a86bd425abc4e672cec0b3290203010001f5758c31782de003d8cd04ca2a2262d6cf1cfabd53255f4f95b102cc2817b355fa9f65a133dc32f1603c9f46d1dd20d13fa2dfabb38747006f006c00640041000000b7e8a99a95eb0597b493457191f27eff80a431cca8bd70b24f0042aa585249e2096ea21012d90d07cb194e87be22d35a6511969c351c455bdbc9a160c55f244be49ae6e6b0a3c1b36d3f0000100085db1758aaa166cb6a54b5e84093f956806fcfd63cc3783269c4216f".decode("hex")
    print "target from 8fbba8c234bf9fa0c05d4fe2773086a8: "
    print hexdump(vm_dconfig)
    print "Baseconfig length: 0x%x (%d) bytes\n" % (len(vm_dconfig), len(vm_dconfig))
    ctx = VmContext(vm_bytecode, vm_cconfig)
    ctx.run()
    if ctx.config == vm_dconfig:
        print "Success!"

