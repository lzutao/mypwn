#!/usr/bin/env python2
import unittest
from mypwn.mycrypto import *
from base64 import b64encode, b64decode

class TestRSACipher(unittest.TestCase):
    def test_bit_length(self):
        from mypwn.mycrypto import _bitLength
        print("\nTesting _bitLength() ...")
        # testcases: each is a tuple (a, b) where _bitLength(a) = b
        testcases = [
            (0, 0),
            (1, 1),
            (1997, 11),
            (2**1024 - 1, 1024),
        ]
        for a, b in testcases:
            result = _bitLength(a)
            self.assertEqual(result, b)

    def test_continued_fraction(self):
        print("\nTesting RSACipher.continued_fraction() ...")
        # test cases: each entry is a tuple
        #   (n, m, pquotients) where pquotients = continued_fraction(n, m)
        testcases = [
            (45, 16, (2, 1, 4, 3)),
            (1, 1, (1,)),
            (1, 2, (0, 2)),
            (5, 15, (0, 3)),
            (27, 73, (0, 2, 1, 2, 2, 1, 2)),
            (73, 27, (2, 1, 2, 2, 1, 2)),
        ]

        for n, m, pquotients in testcases:
            result = RSACipher.continued_fraction(n, m)
            self.assertEqual(result, pquotients)

    def test_iroot(self):
        print("\nTesting RSACipher.iroot() ...")
        # test cases: each entry is a tuple
        #   (x, n, (y, exact)) where y**n = x
        testcases = [
            (1997, 1, (1997, True)),
            (80798284478113, 7, (97, True)),
            (2014460302934265741997296191038900853, 11, (1997, True)),
            (22641335567373305939412534383701517676000422392332377806537267319741840217458496420007, 101, (7, True)),
            (285311670611, 12, (9, False)),
        ]

        for x, n, solution in testcases:
            result = RSACipher.iroot(x, n)
            self.assertEqual(result, solution)

    def test_isqrt(self):
        from mypwn.mycrypto import _iSqrt
        print("\nTesting _iSqrt() ...")
        # testcases: each is a tuple (a, b) where _iSqrt(a) = b
        testcases = [
            (0, 0),
            (1992, 44),
            (1234567890, 35136),
            (3**82, 36472996377170786403),
        ]
        for a, b in testcases:
            result = _iSqrt(a)
            self.assertEqual(result, b)

    def test_gcd(self):
    	print("\nTesting RSACipher.gcd() ...")

    	# test cases: each entry is a triplet (a, b, c) where gcd(a, b) = c
    	testcases = [
    		(13, 13, 13),              # trick case: a = b
			(37, 600, 1),              # first argument is a prime
    	    (20, 100, 20),             # one is multiplum of other
    	    (624129, 2061517, 18913),
    	    (4323874085395, 586898689868986900219865, 85)
		] # straight case

    	for a, b, solution in testcases:
    	    result = RSACipher.gcd(a, b)
    	    self.assertEqual(result, solution)

    def test_extended_gcd(self):
    	print("\nTesting RSACipher.extended_gcd() ...")

    	# test cases: each entry is a tuple
        #   (a, b, (c, x, y)) where a*x + b*y = gcd(a,b) = c
    	testcases = [
    		(97, 150, (1, -17, 11)),
			(180, 150, (30, 1, -1)),
    	    (624129, 2061517, (18913, -33, 10)),
    	    (1914, 899, (29, 8, -17)),
    	    (422, 111, (1, 5, -19)),
		]

    	for a, b, solution in testcases:
    	    result = RSACipher.extended_gcd(a, b)
    	    self.assertEqual(result, solution)

    def test_chinese_remainder(self):
    	print("\nTesting RSACipher.chinese_remainder() ...")

    	# test cases: each entry is a tuple
    	# 	(n, a, x) where x = a_i (mod n_i) for i := 1 -> k
    	testcases = [
    		((3,5,7), (2,3,2), 23),
            ((97, 1997, 2001), (11, 1911, 2), 363591707),
		]

    	for a, b, solution in testcases:
    	    result = RSACipher.chinese_remainder(a, b)
    	    self.assertEqual(result, solution)

    def test_perfectSqrt(self):
        from mypwn.mycrypto import _perfectSqrt
        print("\nTesting _perfectSqrt() ...")

        # test cases: each is a tuple (x, s) if s*s == x,
        # otherwise (x, -1)
        testcases = [
            (4, 2),
            (0, 0),
            (15, -1),
            (25, 5),
            (18, -1),
            (901, -1),
            (1000, -1),
            (1024, 32),
        ]

        for (x, solution) in testcases:
            result = _perfectSqrt(x)
            self.assertEqual(result, solution)


class TestAESCipher(unittest.TestCase):
    def test_ECB_AES(self):
        print("\nTesting AES ECB ...")
        plain = r'flag{do_not_let_machines_win_6a68a292}__________'
        key = b64decode('r7y1dhmTvjQrcra7A1UQFw==')
        ciphertext = 'V3Vqirostg6qW26sle5mnyrwEYSrteN6oHkilO50e9dFkN+0JhC3yu0LcQNw/hXU'

        ecb_cipher = AESCipher(key=key, mode=AESCipher.MODE_ECB)
        solution = ecb_cipher.decrypt(ciphertext)

        self.assertEqual(solution, plain)

    def test_CBC_AES(self):
        print("\nTesting AES CBC ...")
        plain = r'flag{do_not_let_machines_win_6a68a292}'
        key = b64decode('r7y1dhmTvjQrcra7A1UQFw==')
        ciphertext = 'mU5Hq6nHEy1VHvz1q9s55x+/oGDzOaNSj/6pB3KXYla+YG60wXUNBHfmRJEzc6GczmaTIzD9Yd87K5elPG/oVA=='

        ecb_cipher = AESCipher(key=key, mode=AESCipher.MODE_CBC)
        solution = ecb_cipher.decrypt(ciphertext)

        self.assertEqual(solution, plain)


if __name__ == '__main__':
	unittest.main()

