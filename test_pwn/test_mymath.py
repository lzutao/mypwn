#!/usr/bin/env python2
import unittest
from mypwn.mymath import *

class TestMyMath(unittest.TestCase):
	def test_Checksum(self):
		print("\nTesting mypwn.mymath.Checksum class ...")
		filepath = '../LICENSE'
		LICENSE_sha256 = '83915bf9601d28b10378f57d17e47b686e5d584979ebba50ef6eb5ac3d2b654a'
		LICENSE_sha1   = 'b412883eb74a0bb7cd2aa0cb221137678a876ff8'
		LICENSE_md5    = '5a57e6c0fd3f83f420a708ef88294d46'
		self.assertEqual(Checksum.sha256sum(filepath), LICENSE_sha256)
		self.assertEqual(Checksum.sha1sum(filepath), LICENSE_sha1)
		self.assertEqual(Checksum.md5sum(filepath), LICENSE_md5)
		print("    OK.")

	def test_Convert(self):
		print("\nTesting mypwn.mymath.Convert class ...")
		self.assertEqual(Convert.float_to_int(3.14), 1078523331)
		self.assertEqual(Convert.int_to_float(1077936128), 3.0)
		self.assertEqual(Convert.double_to_llong(2.99), 4613915300242936300)
		self.assertEqual(Convert.llong_to_double(4616189618054758400), 4.0)
		print("    OK.")


if __name__ == '__main__':
	unittest.main()
