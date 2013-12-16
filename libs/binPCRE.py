from xstream import xstream


OPCODES=dict(OP_END = 0,OP_SOD = 1,OP_SOM = 2,OP_SET_SOM = 3,OP_NOT_WORD_BOUNDARY = 4,OP_WORD_BOUNDARY = 5,OP_NOT_DIGIT = 6,OP_DIGIT = 7,OP_NOT_WHITESPACE = 8,OP_WHITESPACE = 9,OP_NOT_WORDCHAR = 10,OP_WORDCHAR = 11,OP_ANY = 12,OP_ALLANY = 13,OP_ANYBYTE = 14,OP_NOTPROP = 15,OP_PROP = 16,OP_ANYNL = 17,OP_NOT_HSPACE = 18,OP_HSPACE = 19,OP_NOT_VSPACE = 20,OP_VSPACE = 21,OP_EXTUNI = 22,OP_EODN = 23,OP_EOD = 24,OP_OPT = 25,OP_CIRC = 26,OP_DOLL = 27,OP_CHAR = 28,OP_CHARNC = 29,OP_NOT = 30,OP_STAR = 31,OP_MINSTAR = 32,OP_PLUS = 33,OP_MINPLUS = 34,OP_QUERY = 35,OP_MINQUERY = 36,OP_UPTO = 37,OP_MINUPTO = 38,OP_EXACT = 39,OP_POSSTAR = 40,OP_POSPLUS = 41,OP_POSQUERY = 42,OP_POSUPTO = 43,OP_NOTSTAR = 44,OP_NOTMINSTAR = 45,OP_NOTPLUS = 46,OP_NOTMINPLUS = 47,OP_NOTQUERY = 48,OP_NOTMINQUERY = 49,OP_NOTUPTO = 50,OP_NOTMINUPTO = 51,OP_NOTEXACT = 52,OP_NOTPOSSTAR = 53,OP_NOTPOSPLUS = 54,OP_NOTPOSQUERY = 55,OP_NOTPOSUPTO = 56,OP_TYPESTAR = 57,OP_TYPEMINSTAR = 58,OP_TYPEPLUS = 59,OP_TYPEMINPLUS = 60,OP_TYPEQUERY = 61,OP_TYPEMINQUERY = 62,OP_TYPEUPTO = 63,OP_TYPEMINUPTO = 64,OP_TYPEEXACT = 65,OP_TYPEPOSSTAR = 66,OP_TYPEPOSPLUS = 67,OP_TYPEPOSQUERY = 68,OP_TYPEPOSUPTO = 69,OP_CRSTAR = 70,OP_CRMINSTAR = 71,OP_CRPLUS = 72,OP_CRMINPLUS = 73,OP_CRQUERY = 74,OP_CRMINQUERY = 75,OP_CRRANGE = 76,OP_CRMINRANGE = 77,OP_CLASS = 78,OP_NCLASS = 79,OP_XCLASS = 80,OP_REF = 81,OP_RECURSE = 82,OP_CALLOUT = 83,OP_ALT = 84,OP_KET = 85,OP_KETRMAX = 86,OP_KETRMIN = 87,OP_ASSERT = 88,OP_ASSERT_NOT = 89,OP_ASSERTBACK = 90,OP_ASSERTBACK_NOT = 91,OP_REVERSE = 92,OP_ONCE = 93,OP_BRA = 94,OP_CBRA = 95,OP_COND = 96,OP_SBRA = 97,OP_SCBRA = 98,OP_SCOND = 99,OP_CREF = 100,OP_NCREF = 101,OP_RREF = 102,OP_NRREF = 103,OP_DEF = 104,OP_BRAZERO = 105,OP_BRAMINZERO = 106,OP_MARK = 107,OP_PRUNE = 108,OP_PRUNE_ARG = 109,OP_SKIP = 110,OP_SKIP_ARG = 111,OP_THEN = 112,OP_THEN_ARG = 113,OP_COMMIT = 114,OP_FAIL = 115,OP_ACCEPT = 116,OP_CLOSE = 117,OP_SKIPZERO = 118,OP_TABLE_LENGTH = 119 )
REV_COEDS = dict((v,k) for k, v in OPCODES.iteritems())


#OPCODES=dict(
OP_END = 0
OP_SOD = 1
OP_SOM = 2
OP_SET_SOM = 3
OP_NOT_WORD_BOUNDARY = 4
OP_WORD_BOUNDARY = 5
OP_NOT_DIGIT = 6
OP_DIGIT = 7
OP_NOT_WHITESPACE = 8
OP_WHITESPACE = 9
OP_NOT_WORDCHAR = 10
OP_WORDCHAR = 11
OP_ANY = 12
OP_ALLANY = 13
OP_ANYBYTE = 14
OP_NOTPROP = 15
OP_PROP = 16
OP_ANYNL = 17
OP_NOT_HSPACE = 18
OP_HSPACE = 19
OP_NOT_VSPACE = 20
OP_VSPACE = 21
OP_EXTUNI = 22
OP_EODN = 23
OP_EOD = 24
OP_OPT = 25
OP_CIRC = 26
OP_DOLL = 27
OP_CHAR = 28
OP_CHARNC = 29
OP_NOT = 30
OP_STAR = 31
OP_MINSTAR = 32
OP_PLUS = 33
OP_MINPLUS = 34
OP_QUERY = 35
OP_MINQUERY = 36
OP_UPTO = 37
OP_MINUPTO = 38
OP_EXACT = 39
OP_POSSTAR = 40
OP_POSPLUS = 41
OP_POSQUERY = 42
OP_POSUPTO = 43
OP_NOTSTAR = 44
OP_NOTMINSTAR = 45
OP_NOTPLUS = 46
OP_NOTMINPLUS = 47
OP_NOTQUERY = 48
OP_NOTMINQUERY = 49
OP_NOTUPTO = 50
OP_NOTMINUPTO = 51
OP_NOTEXACT = 52
OP_NOTPOSSTAR = 53
OP_NOTPOSPLUS = 54
OP_NOTPOSQUERY = 55
OP_NOTPOSUPTO = 56
OP_TYPESTAR = 57
OP_TYPEMINSTAR = 58
OP_TYPEPLUS = 59
OP_TYPEMINPLUS = 60
OP_TYPEQUERY = 61
OP_TYPEMINQUERY = 62
OP_TYPEUPTO = 63
OP_TYPEMINUPTO = 64
OP_TYPEEXACT = 65
OP_TYPEPOSSTAR = 66
OP_TYPEPOSPLUS = 67
OP_TYPEPOSQUERY = 68
OP_TYPEPOSUPTO = 69
OP_CRSTAR = 70
OP_CRMINSTAR = 71
OP_CRPLUS = 72
OP_CRMINPLUS = 73
OP_CRQUERY = 74
OP_CRMINQUERY = 75
OP_CRRANGE = 76
OP_CRMINRANGE = 77
OP_CLASS = 78
OP_NCLASS = 79
OP_XCLASS = 80
OP_REF = 81
OP_RECURSE = 82
OP_CALLOUT = 83
OP_ALT = 84
OP_KET = 85
OP_KETRMAX = 86
OP_KETRMIN = 87
OP_ASSERT = 88
OP_ASSERT_NOT = 89
OP_ASSERTBACK = 90
OP_ASSERTBACK_NOT = 91
OP_REVERSE = 92
OP_ONCE = 93
OP_BRA = 94
OP_CBRA = 95
OP_COND = 96
OP_SBRA = 97
OP_SCBRA = 98
OP_SCOND = 99
OP_CREF = 100
OP_NCREF = 101
OP_RREF = 102
OP_NRREF = 103
OP_DEF = 104
OP_BRAZERO = 105
OP_BRAMINZERO = 106
OP_MARK = 107
OP_PRUNE = 108
OP_PRUNE_ARG = 109
OP_SKIP = 110
OP_SKIP_ARG = 111
OP_THEN = 112
OP_THEN_ARG = 113
OP_COMMIT = 114
OP_FAIL = 115
OP_ACCEPT = 116
OP_CLOSE = 117
OP_SKIPZERO = 118
OP_TABLE_LENGTH = 119
#)
#REV_COEDS = dict((v,k) for k, v in OPCODES.iteritems())

def hexx(s):
  r = ''
  for c in s: r+="%02X " % ord(c)
  return r

def singleByte(b):
  if   b == OP_ANY or b == OP_ALLANY or b == OP_ANYBYTE: return "."
  elif b == OP_ANYNL  : return "\\R"
  elif b == OP_CIRC   : return "^"
  elif b == OP_DOLL   : return "$"
  elif b == OP_DIGIT  : return "\\d"
  elif b == OP_WHITESPACE : return "\\s"
  return None

def reClass(data,positive):
  r = ''
  charIndex = 0
  for c in data:
    nc = ord(c)
    cb = 1
    for j in range(8):
      bit = 1 if nc & cb  else 0
      cb *= 2
      if bit == positive: r+= chr(charIndex)
      charIndex += 1
  return r

def readBinary(data):
  verbose = False
  RET=""
  size = len(data)
  xs = xstream(data)
  hdr_names = ('magic','size','opts','flags','dummy1','top_bracket','top_backref','first_byte','req_byte','name_tbl_off','name_entry_size','name_cnt','ref_cnt')
  hdr = xs.readFmt("IIIHHHHHHHHHH", into=hdr_names )
  name_tbl_size = hdr['name_tbl_off'] + hdr['name_entry_size'] * hdr['name_cnt']
   
  hdr['names']=dict()
  xs.seek(hdr['name_tbl_off'])
  for i in range(hdr['name_cnt']):
    idx = xs.readOne('>H')
    name = xs.readN(hdr['name_entry_size'])
    name = name[:name.find("\x00")]
    hdr['names'][idx]=name
  if verbose:
    print hexx(data)
    print hdr
    print "offset : %d " % name_tbl_size 
   
  xs.seek(name_tbl_size);
  pos = name_tbl_size 

  while pos < hdr['size']:
    opcode = xs.readOne("B") 
    opsize = 1

    if verbose:
      print "%d) %d %x | %s \t| %s" % (xs.tell(),opcode,opcode,REV_COEDS[opcode],RET)

    b1 = singleByte(opcode)
    if b1:
      RET += b1
    elif opcode == OP_END:
      if verbose:
        print "end<"
      break
    elif opcode == OP_BRA or opcode == OP_SBRA:
      RET+="(?:"; xs.readN(2)
    elif opcode == OP_KET:      RET+=")"; xs.readN(2)
    elif opcode == OP_CBRA or opcode == OP_SCBRA:
      v1,v2=xs.readFmt(">HH"); 
      if v2 in hdr['names']:    RET+="(?P<%s>" % hdr['names'][v2]
      else:                     RET+="("

    elif opcode == OP_ALT:      RET+="|"; xs.readN(2)
    elif opcode == OP_OPT:      xs.readN(1)
    elif opcode == OP_CHAR or opcode == OP_CHARNC:
      RET+=`xs.readN(1)`.replace("'","")


    elif opcode == OP_CRSTAR      : RET += "*"
    elif opcode == OP_CRPLUS      : RET += "+"
    elif opcode == OP_CRMINPLUS   : RET += "+?"
    elif opcode == OP_CRMINSTAR   : RET += "*?"
    elif opcode == OP_CRRANGE     : RET+= "{%d,%d}" % xs.readFmt(">HH")

    elif opcode == OP_QUERY    : RET += "%s?" % xs.readN(1)

    elif opcode == OP_STAR     :  RET+= "%s*"  % xs.readN(1)
    elif opcode == OP_POSSTAR  :  RET+= "%s*+" % xs.readN(1) 
    elif opcode == OP_MINSTAR  :  RET+= "%s*?" % xs.readN(1)
    
    elif opcode == OP_PLUS     :  RET+= "%s+"  % xs.readN(1)
    elif opcode == OP_POSPLUS  :  RET+= "%s++" % xs.readN(1)
    elif opcode == OP_MINPLUS  :  RET+= "%s+?" % xs.readN(1)
    
    elif opcode == OP_MINQUERY :  RET+= "%s??" % xs.readN(1)

    elif opcode == OP_TYPESTAR     : RET+= "%s*"  % singleByte( xs.readOne("B") )
    elif opcode == OP_TYPEPOSSTAR  : RET+= "%s*+" % singleByte( xs.readOne("B") )
    elif opcode == OP_TYPEMINSTAR  : RET+= "%s*?" % singleByte( xs.readOne("B") ) 

    elif opcode == OP_TYPEPLUS     : RET+= "%s+"  % singleByte( xs.readOne("B") )
    elif opcode == OP_TYPEPOSPLUS  : RET+= "%s++" % singleByte( xs.readOne("B") )
    elif opcode == OP_TYPEMINPLUS  : RET+= "%s+?" % singleByte( xs.readOne("B") )
    
    elif opcode == OP_TYPEMINQUERY : RET+= "%s??" % singleByte( xs.readOne("B") )

    elif opcode == OP_TYPEMINUPTO  : RET+= "%(char)s{,%(cnt)d}?" % dict( cnt=xs.readOne(">H"), char=singleByte( xs.readOne("B") ) ) 
    
    elif opcode == OP_CLASS    : junk=xs.readN(32); RET+="[%s]" % reClass(junk,1)
    elif opcode in [OP_PRUNE]:
      pass
    else:
      if verbose:
        print "CODE :%d " % opcode 
      else:
        pass
    

  if verbose:
    print "\n\nDONE: [%s]\n\n" % RET
  return RET





