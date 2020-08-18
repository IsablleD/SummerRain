#coding:utf-8

import threading
import datetime
import os,sys
import traceback
import struct
import socket
import json
import base64
import util_pki
from gevent.monkey import patch_all
import cmd

patch_all(sys=True)

length = len

class Message:
  def __init__(self):
    self.type = ''
    self.content = ''

class MessageText(Message):
  def __init__(self):
    Message.__init__(self)
    self.type ='text'

class MessageHello(Message):
  def __init__(self):
    Message.__init__(self)
    self.type = 'hello'
    self.name = ''
    self.secret = ''  #临时密钥

class TalkPrint:
  WHITE = '\033[37m'
  GREEN = "\033[32m"
  RED = "\033[31m"
  YELLOW = "\033[93m"
  NEWLN = '\n'
  def __init__(self):
    pass

  def prompt(self):
    # sys.stdout.write(self.GREEN + '>')
    pass

  def text(self,text):
    # sys.stdout.write(self.NEWLN+self.WHITE+text )
    # print self.WHITE,text
    print text

  def send(self,text):
    # sys.stdout.write(self.GREEN + '>'+ text )
    print self.GREEN +  text


  def recv(self,text):
    # sys.stdout.write(self.NEWLN + '\n'+self.YELLOW +'>'+ text + self.NEWLN )
    print self.YELLOW + text

  def error(self,text):
    sys.stdout.write(self.NEWLN + self.RED + text )

class PeerInfo:
  def __init__(self):
    self.name =''
    self.ip = ''
    self.port = 0
    self.pubkey = ''
    self.secret = ''

class Controller(cmd.Cmd):
  def __init__(self):
    cmd.Cmd.__init__(self)
    self.buff=''
    self.local = None
    self.peer = None
    self.talk_print = TalkPrint()
    self.thread = threading.Thread(target=self.acceptRemote)
    self.running = False
    self.sock_server = None
    self.sock_peer = None
    self.secret = ''  # 临时密钥
    self.peer_running = False


  def init(self):
    self.local = PeerInfo()
    self.peer = PeerInfo()

    return self

  def acceptRemote(self):
    self.talk_print.text("Talker start accepting..")

    self.sock_server = socket.socket()
    self.sock_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.sock_server.bind((self.local.ip,self.local.port))
    self.sock_server.listen(1)

    while self.running:
      try:
        peer,addr = self.sock_server.accept()
        self.talk_print.text("new client ..")
        self.sock_peer = peer

        self.peer = PeerInfo()
        # self.peer.secret = self.make_temp_secret()
        threading.Thread(target=self.peerLoop).start()

      except socket.timeout as e:
        pass
      except:
        # traceback.print_exc()
        self.talk_print.error("server has been closed!")

  def peerLoop(self):
      self.buff = ''
      self.peer_running = True
      while self.peer_running :
        try:
          data = self.sock_peer.recv(1000)
          if not data:
            break
          self.buff+=data
          messages,self.buff = self.splitMessage(self.buff)
          for m in messages:
            if m.type == 'text':
              self.processMessageText(m)
            if m.type == 'hello':
              self.processMessageHello(m)
        except:

          break
      self.sock_peer = None
      self.peer_running = False
      self.talk_print.text('Peer lost!')

  def processMessageText(self,message):
    text = util_pki.symm_decrypt(message.content,self.peer.secret)
    self.talk_print.recv(text)

  def loadKey(self,name,type='public'):
    data = open(name+'-'+type+'.key').read()
    return data

  def make_temp_secret(self):
    """生成临时密钥"""
    return util_pki.random_key()

  def processMessageHello(self,message):
    self.peer.name = message.name
    priv_key = self.loadKey(self.local.name,'private')
    message.secret = base64.b64decode(message.secret)
    secret = util_pki.asymm_decrypt(message.secret,priv_key) # 会话密钥
    self.peer.secret = secret

  def splitMessage(self,buff):
    if length(buff) <= 4:
      return []
    messages = []
    while buff:
      data =''
      len, = struct.unpack('!I',buff[:4])
      if length(buff) >= len + 4:
        data = buff[4:4+len]
        buff=buff[4+len:]
      if not data:
        break
      messages.append(self.parseMessage(data))
    return messages,buff

  def parseMessage(self,data):
      jdata =  json.loads(data)
      if jdata['type'] == 'text':
        m = MessageText()
        m.content = jdata.get('content')
        m.content = base64.b64decode(m.content)

      if jdata['type'] == 'hello':
        m = MessageHello()
        m.secret = jdata.get('secret')
        m.name = jdata.get("name")
      return m


  def start(self,args):
    name,ip,port = args
    self.local = PeerInfo()
    self.local.name = name
    self.local.ip = ip
    self.local.port = int(port)
    self.local.pubkey = self.loadKey(self.local.name)
    self.running = True
    self.thread.start()

  def createKey(self,name):
    priv,pub = util_pki.new_pki_keys()
    open(name+'-public.key','w').write(pub)
    open(name+'-private.key','w').write(priv)
    self.talk_print.text("Keys be Created in current Dir.")

  def queryAddress(self,name):
    lines = map(lambda s: s.strip().split(), open('address.txt').readlines())
    addrs = filter(lambda s: len(s) >= 3, lines)
    result = filter(lambda ad: ad[0] == name, addrs)
    if result:
      ip, port = result[0][1:]
      return (ip,port)
    return ()

  def do_start(self,line):
    try:
      name = line
      ip,port = self.queryAddress(name)
      self.start((name,ip,port))
    except:
      print 'error.'


  def do_createKey(self,name):
    self.createKey(name)

  def do_send(self,line):
    line = TalkPrint.GREEN + line
    self.sendMessage( line )

  def do_x(self,line):
    self.do_send(line)

  def do_conn(self,line ):
    """https://pymotw.com/2/cmd/"""
    try:
      name = line
      ip,port = self.queryAddress(name)
      if self.sock_peer == None:
        self.doCommandConnect((name,ip,port))
    except:
      print "error"

  def complete_conn(self, text, state):
    return ['bob','127.0.0.1',7002]

  def do_close(self,line):
    if self.sock_peer:
      self.doCommandClose()

  def do_quit(self,line):
    self.doCommandQuit()
    return True

  def do_q(self,line):
    self.do_quit(line)

  def sendMessage(self,text):
    if self.sock_peer:
      m = MessageText()
      m.content = util_pki.symm_encrypt(text, self.peer.secret)  # 加密内容
      m.content = base64.b64encode(m.content)
      jdata = json.dumps(m.__dict__)
      data = struct.pack('!I', length(jdata)) + jdata
      self.sock_peer.sendall(data)

  def run(self):
    self.cmdloop()

  def doCommandConnect(self,args):
    ''' args:
          name : peer name
          ip
          port
      conn bob 127.0.0.1 7002
    '''
    try:
      if len(args)!=3:
        self.talk_print.error("arguments error: conn peer_name ip port ")
        return
      peer_name,ip,port = args
      self.sock_peer = socket.socket()
      self.sock_peer.connect((ip,int(port)))

      # send Hello
      self.peer = PeerInfo()
      self.peer.name = peer_name
      self.peer.secret = self.make_temp_secret()
      self.peer.pubkey = self.loadKey(peer_name)

      message = MessageHello()
      message.name =  self.local.name
      message.secret = util_pki.asymm_encrypt(self.peer.secret,self.peer.pubkey)
      message.secret = base64.b64encode(message.secret)

      data = message.__dict__
      jdata = json.dumps(data)
      data = struct.pack('!I',len(jdata))
      data = data + jdata
      self.sock_peer.sendall(data)

      threading.Thread(target=self.peerLoop).start()

    except:
      traceback.print_exc()
      self.sock_peer = None
      self.talk_print.error("command conn error. please retry..")

  def doCommandClose(self):
    if self.sock_peer:
      self.sock_peer.close()
      self.sock_peer = None
    self.talk_print.text("connection close!")

  def doCommandQuit(self):
    if self.sock_server:
      self.sock_server.close()
    if self.sock_peer:
      self.sock_peer.close()
    self.running = False
    self.peer_running = False


if __name__ == '__main__':
  Controller().init().run()



"""
cmd 

https://pymotw.com/2/cmd/


pycrypto

https://blog.csdn.net/u010693827/article/details/78629268?utm_medium=distribute.wap_relevant.none-task-blog-BlogCommendFromMachineLearnPai2-2.nonecase&depth_1-utm_source=distribute.wap_relevant.none-task-blog-BlogCommendFromMachineLearnPai2-2.nonecase

from Crypto import Random
from Crypto.PublicKey import RSA

rg = Random.new().read
rsa = RSA.generate(1024,rg)
rsa.exportKey()
rsa.publickey().exportKey()


tcpdump 
=======
sudo tcpdump -i en0 -nn tcp dst port 80

"""