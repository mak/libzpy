


def dumper(data,verb,byId='-1',mask=0,outfile=None):
  if not outfile:
    raise Exception("dumper: need outfile !")

  verb("Dumping items : %s " % byId )
  itemsId = map( int , byId.split(',') )

  for item in data['items']:
    if item['recId'] in itemsId :
      verb("Found record id=%d " % item['recId'])
      with open(outfile,'wb') as f:
        f.write(item['data'])



