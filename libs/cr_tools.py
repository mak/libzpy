





def xorWithKey(data,key):
  key_len = len(key)
  data_len = len(data)
  out = ""
  i = 0 
  while i < data_len:
    c = ord(data[i])
    k = ord(key[i%key_len])
    v = c ^ k
    out += chr(v)
    i+=1
  return out






