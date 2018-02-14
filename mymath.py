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


class Checksum():
  @staticmethod
  def _hashlib_wrapper(method, filename, block_size):
    check_sum_fun = method()
    with open(filename, 'rb') as fd:
      for block in iter(lambda: fd.read(block_size), b''):
        check_sum_fun.update(block)
    return check_sum_fun.hexdigest()

  @staticmethod
  def sha256sum(filename, block_size=65536):
    '''Return sha256 sum of a file
    Efficency when works with many file
    '''
    return Checksum._hashlib_wrapper(hashlib.sha256, filename, block_size)

  @staticmethod
  def sha1sum(filename, block_size=65536):
    '''Return sha1 sum of a file'''
    return Checksum._hashlib_wrapper(hashlib.sha1, filename, block_size)

  @staticmethod
  def md5sum(filename, block_size=65536):
    '''Return md5 sum of a file'''
    return Checksum._hashlib_wrapper(hashlib.md5, filename, block_size)
