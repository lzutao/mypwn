#!/usr/bin/env python2
# -*- coding: utf-8 -*-

__all__ = [
    'unhex',
  ]

def unhex(s):
  ''' unhex('0xa414243L\n') -> '\nABC'
  '''
  if isinstance(s, basestring):
    s = s.strip()
    s = s.replace('0x', '')
  elif isinstance(s, (int, long)):
    s = hex(s)[2:]
  else:
    raise TypeError("Type must be string or intergral.")

  val = s.replace('L', '')

  if len(val) % 2 != 0:
    val = '0' + val
  return val.decode('hex')

