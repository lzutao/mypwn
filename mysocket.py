#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import socket
import telnetlib
import sys
from log import *

__all__ = [
    'myconnect',
    'recvuntil',
    'telnet',
  ]

def myconnect(host, port):
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  log.info("Connecting to (%s %d) ..." % (host, port))
  sock.connect((host, port))
  log.indented("Connected")
  return sock

def recvuntil(s, pattern):
  buf = ''
  while pattern not in buf:
    buf += s.recv(1)
  return buf

def telnet(s):
  log.info('Telneting to socket ...')
  t = telnetlib.Telnet()
  t.sock = s
  t.interact()

