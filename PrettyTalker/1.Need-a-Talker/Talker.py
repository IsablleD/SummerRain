#coding:utf-8
import os
import sys
import traceback
import datetime
import cmd
import threading
import struct # 字节序列化
import socket  # 通信接口
import base64 # 消息编码
import json  # 消息编码
import util_pki

from gevent.monkey import patch_all

patch_all(sys=True )


length = len
class Message(object):
  def __init__(self):
    self.type = ''  # 消息类型
    self.content = ''

class MessageText(Message):
  def __init__(self):
    Message.__init__(self)
    self.type = 'text'  # 文本消息

class MessageHello(Message):
  def __init__(self):
    Message.__init__(self)
    self.type = 'hello'
    self.name = ''  # 发送方（动态密钥产生方的名字 alice)
    self.secret = '' # 动态密钥 RSA(K)

class PeerInfo(object):
  """表示通信两端对象配置信息"""
  def __init__(self):
    self.name ='' # 端点名称 alice /bob
    self.ip = ''
    self.port = 0
    self.pubkey = ''
    self.secret = ''

class TalkPrint:
  """消息提示输出"""
  def __init__(self):
    pass

  def text(self,text):
    print text

  def send(self,text):
    print text

  def recv(self,text):
    print "\033[32m",text  # GREEN

  def error(self,text):
    print "\033[31m",text # RED

class Controller(cmd.Cmd):
  """Talker总体控制类 """
  def __init__(self):
    cmd.Cmd.__init__(self)
    self.buff = '' # 接收数据缓冲
    self.sock_server = None # 接收别人拨号
    self.sock_peer = None # 外拨号的插口
    self.secret = ''
    self.running = False
    self.peer_running = False
    self.thread = threading.Thread(target=self.acceptRemote)
    self.local = None # 本地 peer info
    self.peer = None # 远端
    self.talk_print = TalkPrint() # 消息输出

  def init(self):
    self.local = PeerInfo()
    self.peer = PeerInfo()
    return self

  def run(self):
    return self.cmdloop()

  def queryAddress(self,name):
    lines = map(lambda  s: s.strip().split() , open('address.txt').readlines())
    addrs = filter(lambda  s: len(s) >=3 ,lines)
    result = filter(lambda  ad:ad[0] == name,addrs)
    if result:
      ip,port = result[0][1:]
      return (ip,port)
    return ()

  def acceptRemote(self):
    """远端呼叫进入线程处理"""
    self.talk_print.text("Talker start accepting..")
    self.sock_server = socket.socket()
    self.sock_server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    self.sock_server.bind((self.local.ip,self.local.port))
    self.sock_server.listen(1)

    while self.running:
      try:
        peer,addr = self.sock_server.accept()
        self.talk_print.text("new client incoming : " + str(addr))
        self.sock_peer = peer
        self.peer = PeerInfo()
        threading.Thread(target=self.peerLoop).start() # 启动客户连接线程
      except:
        self.talk_print.error("server be closed!")


  def splitMessage(self,buff):
    """解封包
      @:return:  messages, buff   可用消息，剩余buff
    """
    if length(buff) <= 4:
      return (),buff
    messages = []
    while buff:
      data = ''
      size, = struct.unpack('!I',buff[:4])
      if length(buff) >= size + 4:
        data = buff[4:4+size]
        buff=buff[4+size:]
      if not data :
        break
      m = self.parseMessage(data)
      messages.append(m)
    return messages,buff

  def parseMessage(self,data):
    """分解消息"""
    jdata = json.loads(data)
    if jdata['type'] == 'text':
      m = MessageText()
      m.content = jdata.get('content')
      m.content = base64.b64decode(m.content)

    if jdata['type'] == 'hello':
      m = MessageHello()
      m.secret = jdata.get('secret')
      m.name = jdata.get('name')

    return m


  def processMessageText(self,message):
    """文本消息"""
    text = message.content # ?? 解密  todo.
    text = util_pki.symm_decrypt(message.content,self.peer.secret)
    self.talk_print.recv(text)

  def processMessageHello(self,message):
    self.peer.name = message.name
    priv_key = self.loadKey(self.local.name,'private')
    message.secret = base64.b64decode(message.secret)
    secret = util_pki.asymm_decrypt(message.secret,priv_key)
    # 用我的私钥解开共享加密密钥
    self.peer.secret = secret


  def peerLoop(self):
    """处理远端进入连接的消息接收"""
    self.buff =''
    self.peer_running = True # 远端可用
    while self.peer_running:
      try:
        data = self.sock_peer.recv(1000)
        if not data: # 对方可能挂断 shutdown (half close , full close)
          break
        self.buff += data
        messages,self.buff = self.splitMessage(self.buff)
        for m in messages:
          if m.type == 'text':
            self.processMessageText(m)
          if m.type == 'hello':
            self.processMessageHello(m)

      except:
        traceback.print_exc()
        break

    self.sock_peer = None
    self.peer_running = False
    self.talk_print.text("Peer Connection Lost!")

  def start(self,args):
    """侦听服务端口 tcp """
    name,ip,port = args
    self.local = PeerInfo()
    self.local.name = name
    self.local.ip = ip
    self.local.port = int(port)
    self.local.pubkey = self.loadKey(self.local.name)
    self.running = True
    self.thread.start()

  def loadKey(self,name,type='public'):
    """查找共钥信息"""
    data = open(name+'-'+type+'.key').read()
    return data

  def createKey(self,name):
    priv,pub = util_pki.new_pki_keys()
    open(name+'-public.key','w').write(pub)
    open(name+'-private.key','w').write(priv)

    self.talk_print.text('Keys has been Created!')

  def doCommandConnect(self,args):
    """发起连接，并发送密钥协商 hello"""
    try:
      peer_name,ip,port = args
      self.sock_peer = socket.socket()
      self.sock_peer.connect((ip,int(port)))

      # connected
      self.peer = PeerInfo()
      self.peer.name = peer_name
      self.peer.secret = util_pki.random_key() # 对称加密密钥
      self.peer.pubkey = self.loadKey(peer_name)

      # 发送密钥 hello
      message = MessageHello()
      message.name = self.local.name
      message.secret = util_pki.asymm_encrypt(self.peer.secret,self.peer.pubkey)
      message.secret = base64.b64encode(message.secret)

      # message serialization
      data = message.__dict__
      jdata = json.dumps(data)

      #封包
      data = struct.pack('!I',len(jdata))
      data = data + jdata

      # send it out
      self.sock_peer.sendall(data)

      # init recieve thread
      threading.Thread(target=self.peerLoop).start()
    except:
      traceback.print_exc()
      self.sock_peer = None
      self.talk_print.error('Connect error!')


  def do_start(self,line):
    """  start alice/bob """
    try:
      name = line
      ip,port = self.queryAddress(name)
      self.start((name,ip,port))
    except:
      pass

  def do_createKey(self,name):
    """创建用户的公私钥对"""
    self.createKey(name)

  def do_conn(self,line):
    """发起对远端连接 conn alice"""
    try:
      name = line
      ip,port = self.queryAddress(name)
      if self.sock_peer == None:
        self.doCommandConnect((name,ip,port))
    except:
      self.talk_print.error("connect peer error!")

  def do_send(self,line):
    """发送消息  send  xxxxooo """
    self.sendMessage(line)

  def do_close(self,line):
    if self.sock_peer:
      self.doCommandClose()

  def do_quit(self,line):
    self.doCommandQuit()

  def doCommandClose(self):
    if self.sock_peer:
      self.sock_peer.close()
      self.sock_peer = None
    self.talk_print.text('connection be closed')

  def doCommandQuit(self):
    if self.sock_server:
      self.sock_server.close()
    if self.sock_peer:
      self.sock_peer.close()
    self.running = False
    self.peer_running = False

  def sendMessage(self,text):
    """发送消息到远端
      消息加密
    """
    if self.sock_peer:
      m = MessageText()
      m.content = util_pki.symm_encrpyt(text,self.peer.secret)
      m.content = base64.b64encode(m.content)
      jdata = json.dumps(m.__dict__)
      data = struct.pack('!I',length(jdata)) + jdata

      self.sock_peer.sendall(data)

if __name__ == '__main__':
  Controller().init().run()