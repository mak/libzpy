#!/usr/bin/python

import argparse
import types
import os
import sys
import json 
import pkgutil
import re


PARSER_DIR = "modules"
VERBOSE =False

def verb(m): 
  if VERBOSE: 
    print "[v] %s" % m;

def die(m):  
  print m;  
  sys.exit();


def showAvailable():
  verb("Loading mods ...")
  path = os.path.abspath(__file__)
  dir_path = os.path.dirname(path)
  try:
    modPath = dir_path+'/'+PARSER_DIR  
    verb("Module path : %s " % modPath )
    for _, mod ,_ in pkgutil.iter_modules( [ modPath ] ):
     verb("File : %s"%mod)
     handle = __import__(PARSER_DIR+"."+mod)
     handle = getattr(handle,mod)
     doc=`handle.__doc__`
     for t in MODULES:
       pre = t+'_'
       if mod.find(pre) > -1:
         name = mod.replace( pre, '' )
         MODULES[t]['elements'][name]=dict(doc=doc, handle=handle)
  except Exception,e :
    die("Fail to load modules! (%s) " % `e`)


  print '> Available modules : '
  for t in MODULES:
    print " # %s " % MODULES[t]['name']
    for m in MODULES[t]['elements']:
      print "   * %s (%s)" % ( m,MODULES[t]['elements'][m]['doc'])



def processElement(elem):  ## format : pkg/class::method?args=val&arg2=val2 
  patt = r'(?P<mod>[^/]*)/(?P<func>[^?]*)([?](?P<args>.*))?'  
  #print patt
  res = re.search(patt,elem)
  if not res:
    raise Exception("Fail to parse line !")
  vals = res.groupdict()
  modName = PARSER_DIR+'.'+vals['mod']
  mHandle = __import__(modName)
  mHandle = getattr(mHandle,vals['mod'])

  if vals['func'].find("::") > -1 : # class + func
    cls,fnc = vals['func'].split("::")
    clsHandle = getattr(mHandle,cls)
    parHandle = clsHandle()
    fnHandle = getattr(parHandle,fnc)
  else:
    parHandle = mHandle
    fnHandle  = getattr(parHandle,vals['func'])

  if vals['args']: 
    args = dict( (n,v) for n,v in (a.split('=') for a in vals['args'].split('&') ) )
  else:
    args = dict()

  RV=dict( par=parHandle , func=fnHandle , args=args )
  return RV





P = argparse.ArgumentParser(description='== ZeuS-like BinStorage Parse ==')
P.add_argument('--info'    , default=None,          help='Show info of sub-module', type=str )
P.add_argument('--show'    , action='store_true',   help='List available sub-modules' )
P.add_argument('--verbose' , action='store_true',   help='Be Verbose!' )

P.add_argument('--fin'     , default=None  ,        help='Input file' , type=str )
P.add_argument('--skip'    , default=0     ,        help='[only when --extract ] Skip N Bytes ',  type=int )

P.add_argument('--do'      , default=None  ,        help="Add sub-module to chain ", type=str,  action='append' , dest='actions' )

args = P.parse_args()

## --pre  'module:function(params)'
## --post  ''

if args.verbose:
  VERBOSE = True

if args.info:
  ShowInfo(args.info)
  die()

if args.show:
  showAvailable()
  die()

if not args.fin :
  die("Need input file !")

if not args.actions :
  die("Please add at least one --do  :)")

CHAIN = []

for elem in args.actions:
  try:
    x = processElement(elem)
    #print x
    CHAIN.append(x)
  except Exception, e:
    die("Fail to process element [%s], reason : %s " % (elem,`e`))

verb("Work work ... ")

try:
  data = open(args.fin,'r').read(999999)
  verb("Got [%d] bytes from file" % len(data))  
 
  if args.skip:
    verb("Skipping %d bytes ..." % args.skip )
    data = data[args.skip:]
  
  for elem in CHAIN:
    verb(`elem`)
    data = elem['func'](data,verb,**elem['args']) 

except Exception,e:
  print "Error! python said : %s " % `e`






