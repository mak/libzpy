#!/usr/bin/env python

from socket import *
import thread
import json,base64,os


import SocketServer


for m in os.listdir('modules'):
    



class Server(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

class handler(SocketServer.StreamRequestHandler):
    def handle(self):
        
        try:
            data = json.load(self.rfile)
            cfg = base64.b64decode(data['cfg'])
            type = data['type'].lower()
            if type not in MODULES:
                
            parser = __import__('modules.'+type)
            parser = getattr(parser,type)
            print "[*] Recived data - decoding"
            c=getattr(parser,'go')(cfg,lambda x:x)
            print c
            d=datetime.datetime.now().strftime('%s')
            with open('/tmp/%s.%d.cfg'%(type,d)) as f: f.write(c)
            print '[*] Config saved in /tmp/%s.%d.cfg'%(type,d)
            del data['cfg']; del data['type']
            for h in data:
                print `h`

        except ValueError as e:
            print "Something wrong " + `e`
        


if __name__ == '__main__':

    server = Server(('0.0.0.0', 7124), handler)
    server.serve_forever()
