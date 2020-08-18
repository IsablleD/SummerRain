#coding:utf-8

from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.PublicKey import RSA

from Crypto.Cipher import AES

import base64

# 加密解密：公钥

def new_pki_keys():
  rg = Random.new().read
  rsa = RSA.generate(1024,rg)
  priv_key = rsa.exportKey()
  pub_key = rsa.publickey().exportKey()
  return priv_key,pub_key

def asymm_encrypt(text,pub_key):
  key = RSA.importKey(pub_key)
  cipherText = Cipher_pkcs1_v1_5.new(key).encrypt(text)
  return cipherText

def asymm_decrypt(ciphertext,priv_key):
  rg = Random.new().read
  key = RSA.importKey(priv_key)
  text = Cipher_pkcs1_v1_5.new(key).decrypt(ciphertext,rg)
  return text

def asymm_sign(text,priv_key):
  key = RSA.importKey(priv_key)
  signer = Signature_pkcs1_v1_5.new(key)
  hash = SHA.new()
  hash.update(text)
  signtext = signer.sign(hash)
  return signtext

def asymm_verify(text,signtext,pub_key):
  key = RSA.importKey(pub_key)
  signer = Signature_pkcs1_v1_5.new(key)
  hash = SHA.new()
  hash.update(text)
  okay = signer.verify(hash,signtext)
  return okay

def symm_encrypt(text,key):
  BS = AES.block_size
  pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
  unpad = lambda s: s[0:-ord(s[-1])]

  cryptor = AES.new(key, AES.MODE_CBC, key)
  ciphertext = cryptor.encrypt(pad(text))
  return ciphertext

def symm_decrypt(ciphertext,key):
  BS = AES.block_size
  unpad = lambda s: s[0:-ord(s[-1])]
  cryptor = AES.new(key, AES.MODE_CBC, key)
  text = unpad(cryptor.decrypt(ciphertext))
  return text


def random_key(len=16):
  import os
  key = os.urandom(len)
  return key


def hex_dump( bytes):
  dump = ' '.join(map(lambda _: '%02x' % _, map(ord, bytes)))
  return dump


def test_asymm():
  priv_key,pub_key = new_pki_keys()
  print priv_key
  print pub_key

  ciphertext = asymm_encrypt('hello',pub_key)
  text = asymm_decrypt(ciphertext,priv_key)

  signtext = asymm_sign('hello',priv_key)

  print text
  signtext = base64.b64encode(signtext)
  print signtext
  signtext = base64.b64decode(signtext)
  print asymm_verify(text,signtext,pub_key)

def test_symm():
  share_key = random_key()
  ciphertext = symm_encrypt('hello',share_key)

  text = symm_decrypt(ciphertext,share_key)
  print text

  print hex_dump(ciphertext)
  print hex_dump(share_key)

if __name__ == '__main__':
  test_asymm()
  test_symm()