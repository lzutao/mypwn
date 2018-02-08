#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import hashlib
from struct import pack, unpack

__all__ = [
    'p32', 'u32', 'p64', 'u64', 'Convert', 'Checksum',
]

def p32(s):
  return pack('<I', s)

def u32(s):
  return unpack('<I', s)[0]

def p64(s):
  return pack('<Q', s)

def u64(s):
  return unpack('<Q', s)[0]


class Convert():
  """Convert from a type to new type"""
  @staticmethod
  def float_to_int(f):
    ''' float_to_int(3.14) -> 1078523331
    '''
    s = pack('<f', f)
    return u32(s)

  @staticmethod
  def int_to_float(d):
    ''' int_to_float(1077894185) -> 2.99
    '''
    s = p32(d)
    return unpack('<f', s)[0]

  @staticmethod
  def double_to_llong(lf):
    ''' double_to_llong(2.99) -> 4613915300242936300'''
    s = pack('<d', lf)
    return u64(s)

  @staticmethod
  def llong_to_double(ll):
    '''llong_to_double(4614770984172136694) -> 3.37'''
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
