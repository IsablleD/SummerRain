#coding:utf-8

"""
util_pki.py

随机共享密钥
对称加密，解密
非对称加密，解密
签名和验签名

"""

from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.Cipher import  AES
import base64


def new_pki_keys():
  """生成公私钥对"""
  rg = Random.new().read
  rsa = RSA.generate(1024,rg)
  priv_key = rsa.exportKey()
  pub_key = rsa.publickey().exportKey()
  return priv_key,pub_key


def asymm_encrypt(text,pub_key):
  """非对称加密"""
  key = RSA.importKey(pub_key)
  cipherText = Cipher_pkcs1_v1_5.new(key).encrypt(text)
  return cipherText

def asymm_decrypt(ciphertext,priv_key):
  """非对称解密 """
  rg = Random.new().read
  key = RSA.importKey(priv_key)
  text = Cipher_pkcs1_v1_5.new(key).decrypt(ciphertext,rg)
  return text


def symm_encrpyt(text,key):
  """对称加密 AES 128bit """
  BS = AES.block_size # 128
  pad = lambda  s:s +(BS-len(s)%BS)* chr(BS - len(s)%BS)
  cryptor = AES.new(key,AES.MODE_CBC,key)
  ciphertext = cryptor.encrypt(pad(text))
  return ciphertext

def symm_decrypt(ciphertext,key):
  """对称解密 AES 128 """
  BS = AES.block_size
  unpad = lambda  s: s[0:-ord(s[-1])]

  cryptor = AES.new(key,AES.MODE_CBC,key)
  text = unpad(cryptor.decrypt(ciphertext))
  return text

def random_key(len=16):
  """随机密码"""
  import os
  return os.urandom(len)


