#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import hashlib
from struct import pack, unpack

__all__ = [
    'p32', 'u32', 'p64', 'u64', 'Convert', 'Checksum',
]

def p32(s):
  '''
  Returns a string containing value s packed to the
  little-endian unsigned int format (4 bytes)
  '''
  return pack('<I', s)

def u32(s):
  '''
  Returns a little-endian unsigned int that packed by the string s
  '''
  return unpack('<I', s)[0]

def p64(s):
  '''
  Returns a string containing value s packed to the
  little-endian unsigned long long format (8 bytes)
  '''
  return pack('<Q', s)

def u64(s):
  '''
  Returns a little-endian unsigned long long that packed by the string s
  '''
  return unpack('<Q', s)[0]


class Convert():
  """Convert from a type to new type"""
  @staticmethod
  def float_to_int(f):
    '''
    Returns a string containing value f packed to the
    little-endian float format (4 bytes)
    '''
    s = pack('<f', f)
    return u32(s)

  @staticmethod
  def int_to_float(d):
    '''
    Returns a little-endian float that packed by the string d
    '''
    s = p32(d)
    return unpack('<f', s)[0]

  @staticmethod
  def double_to_llong(lf):
    '''
    Returns a string containing value lf packed to the
    little-endian double format (8 bytes)
    '''
    s = pack('<d', lf)
    return u64(s)

  @staticmethod
  def llong_to_double(ll):
    '''
    Returns a little-endian double that packed by the string ll
    '''
    s = p64(ll)
    return unpack('<d', s)[0]

