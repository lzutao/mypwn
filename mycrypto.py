#!/usr/bin/python
# -*- coding: utf-8 -*-

# In Debian, install `apt install python-crypto`

__all__ = ['AESCipher', 'RSACipher']

from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode, b64decode

try:
    import gmpy2
    _bitLength = gmpy2.bit_length
    _divMod = gmpy2.f_divmod
    _extendedGCD = gmpy2.gcdext
    _gcd = gmpy2.gcd
    _iRoot = gmpy2.iroot
    _iSqrt = gmpy2.isqrt
    def _perfectSqrt(x):
        s, r = gmpy2.isqrt_rem(x)
        return s if r == 0 else -1
    # f_mod(x, y int) -- The remainder will have the same sign as y
    _mod = gmpy2.f_mod
    _modInverse = gmpy2.invert
    _mulProduct = gmpy2.mul
    _mpz = gmpy2.mpz
except ImportError:
    try:
        int.bit_length(1)
        def _bitLength(x):
            return x.bit_length()
    except AttributeError:
        def _bitLength(x):
            '''
            Calculates the bit length of x
            '''
            assert x >= 0
            n = 0
            while x > 0:
                n += 1
                x >>= 1
            return n

    def _divMod(x, y):
        '''
        Returns the quotient and remainder of x divided by y.
        The quotient is floor rounding and the remainder will have the same sign as y.
        x and y must be integers.
        '''
        return divmod(x, y)

    def _extendedGCD(a, b):

        '''Returns (g, x, y) and such that a*s + b*t = g and g = gcd(a,b)'''

        (s, old_s) = (0, 1)
        (t, old_t) = (1, 0)
        (r, old_r) = (b, a)

        while r != 0:
            (div, mod) = _divMod(old_r, r)
            (old_r, r) = (r, mod)
            (old_s, s) = (s, old_s - div * s)
            (old_t, t) = (t, old_t - div * t)

        g, x, y = old_r, old_s, old_t
        return (g, x, y)

    def _gcd(a,b):
        from fractions import gcd as greatest_common_divisor
        return greatest_common_divisor(a, b)

    def _iRoot(x, n):
        lo, hi = -1, (x + 1)
        while (lo + 1) < hi:
            y = (lo + hi) // 2
            p = y**n
            if p < x:
                lo = y
            else:
                hi = y
        exact = ((hi**n) == x)
        y = hi if exact else lo
        return (y, exact)

    def _iSqrt(n):
        '''Returns the integer square root of n (int) and n >= 0.'''
        if n < 0:
            raise ValueError('Negative numbers: n = %d'%(n))
        elif n == 0:
            return 0
        a,b= _divMod(_bitLength(n), 2)
        x = 2**(a+b)
        y = (x + n//x)//2
        while True:
            y = (x + n//x)//2
            if y >= x:
                return x
            x = y
        return x

    def _perfectSqrt(x):
        '''
        Returns s if s*s = x else -1
        '''
        last_hexdigit = x & 0xf
        notPerfectList = [2, 3, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15]
        if (last_hexdigit in notPerfectList):
            return - 1
        s = _iSqrt(x)
        return s if s*s == x else -1

    def _modInverse(a, m):
        '''Returns x (int) such that a*x = 1 (mod m)'''
        (g, x, _) = _extendedGCD(a, m)
        return (x % m) if g == 1 else 0

    def _mulProduct(a, b):
        return a*b

    def _mpz(n=0): return n

    def _mod(a,b): return a%b


class RSACipher(object):

    """Mostly stuffs for RSA"""

    @staticmethod
    def continued_fraction(n, m=1):
        '''
        Returns continued fraction `pquotients' in form (a0, a1, .., a_n)
        of a rational p/q

        Example:
        >>> continued_fraction(45, 16)
        (2, 1, 4, 3)
        >>>

        Algorithm:
        Using GCD algorithm
            n   =   q × m   +   r
            =====================
            45  =   2 × 16  +   13
            16  =   1 × 13  +   3
            13  =   4 × 3   +   1
            3   =   3 × 1   +   0
        '''
        q, r = _divMod(n, m)
        partial_quotients = [q]
        while r != 0:
            n, m = m, r
            q, r = _divMod(n, m)
            partial_quotients.append(q)
        return tuple(partial_quotients)

    @staticmethod
    def continued_fraction_convergents(pquotients):
        '''
        Returns iterator to list of convergents (rational approximations)
        of the continued fraction in form of (n, m), equivalent with n/m

        Note:
        + Even-numbered convergents are smaller than the original number,
        while odd-numbered ones are bigger.

        Example:
        >>> pquotients = continued_fraction(73, 27)
        >>> print(pquotients)
        (2, 1, 2, 2, 1, 2)
        >>> c = continued_fraction_convergents(pquotients)
        >>> print(list(c))
        [(2, 1), (3, 1), (8, 3), (19, 7), (27, 10), (73, 27)]
        >>>

        Reference:
        + https://oeis.org/wiki/Continued_fractions
        '''
        if len(pquotients) == 0:
            yield (0, 1)
        else:
            p_2, q_2 = 0, 1
            p_1, q_1 = 1, 0
            for a_i in pquotients:
                p = a_i*p_1 + p_2 # p[i] = a[i]*p[i-1] + p[i-2]
                q = a_i*q_1 + q_2 # q[i] = a[i]*q[i-1] + q[i-2]
                p_2, p_1 = p_1, p
                q_2, q_1 = q_1, q
                c = (p, q) # c_i = p_i / q_i, i>=0
                yield c

    @staticmethod
    def gcd(a,b):
        return _gcd(a,b)

    @staticmethod
    def extended_gcd(a, b):

        '''Returns (g, x, y) and such that a*x + b*y = g and g = gcd(a,b)'''
        return _extendedGCD(a, b)

    @staticmethod
    def mod_inverse(a, m):

        '''Returns x (int) such that a*x = 1 (mod m)'''
        x = _modInverse(a, m)
        if x == 0:
            raise ValueError('No x such that %d*x = 1 (mod %d)'%(a, m))
        return x

    @staticmethod
    def chinese_remainder(n, a):
        '''
        Returns x (int) such that
            x = a_i (mod n_i) for i := 1 -> k

        Reference: https://rosettacode.org/wiki/Chinese_remainder_theorem
	    '''

        prod = reduce(_mulProduct, n) # reduce is faster than equivalent for loop
        total = _mpz(0)
        for (n_i, a_i) in zip(n, a):
            p = prod // n_i
            total += a_i * RSACipher.mod_inverse(p, n_i) * p
        return _mod(total, prod)

    @staticmethod
    def iroot(x, n):
        '''
        Returns (y, exact) (int, bool) such that y**n = x
        @param n: (int) > 0
        @param x: (int) >= 0
        '''
        return _iRoot(x, n)

    @staticmethod
    def hastad_broadcast_attack(N, C):
        '''
        Retunrs plain text m in form long type such that e=len(N)=len(C) and
        e is small and we knew `e' pairs module n, ciphertext c

        In short, returns m if
            c_i = (m**k) (mod n_i) for i: 1->k
        With chinese remainder theorem:
            c'  = (m**k) (mod n_1*n_2*..*n_k) for i: 1->k
	    '''
        e = len(N)
        assert(e == len(C))
        remainder = RSACipher.chinese_remainder(N, C)
        for (n, c) in zip(N, C):
            assert(_mod(remainder, n) == c)
        m, exact = RSACipher.iroot(remainder, e)
        assert(exact)
        return m

    @staticmethod
    def wiener_attack(e, n):
        '''
        Returns d knowing (e, n) applying the Wiener continued fraction attack
        -------------------------------
        RSA-keys are Wiener-vulnerable if d < (n^(1/4))/sqrt(6)

        The RSA keys are obtained as follows:
        1. Choose two prime numbers p and q
        2. Compute n=p*q
        3. Compute phi(n)=(p-1)*(q-1)
        4. Choose e such that 1 < e < phi(n); e and phi(n) are coprime
        5. Compute d = e^(-1) (mod phi(n))
        6. e is the public key;
           n is also made public (determines the block size);
           d is the private key

        Encryption is as follows:
        1. Size of data to be encrypted must be less than n
        2. ciphertext=pow(plaintext, e, n)

        Decryption is as follows:
        1. Size of data to be decrypted must be less than n
        2. plaintext=pow(ciphertext, d, n)
        '''
        frac = RSACipher.continued_fraction(e, n)
        convergents = RSACipher.continued_fraction_convergents(frac)

        for (k, d) in convergents:
            #check if d is actually the key
            if (k != 0) and ((e*d - 1)%k == 0):
                phi = (e*d - 1)//k
                s   = n - phi + 1
                # check if the equation x^2 - s*x + n = 0
                # has integer roots
                discr = s*s - 4*n
                if discr >= 0:
                    t = _perfectSqrt(discr)
                    if (t != -1) and ((s+t)%2 == 0):
                        return d
        return -1


class AESCipher(object):
    '''
    Reference:
    + http://pythonhosted.org/pycrypto/
    '''

    MODE_ECB = AES.MODE_ECB
    MODE_CBC = AES.MODE_CBC

    def __init__(self, key, mode=AES.MODE_ECB):

        # key (byte string) - The secret key to use in the symmetric cipher.
        #     It must be 16 (AES-128), 24 (AES-192), or 32 (AES-256) bytes long.
        # key must be hash by sha256, md5 before pass to this class
        # Why hash key? To len(key) in AES.key_size

        assert mode in (AES.MODE_ECB, AES.MODE_CBC)
        assert len(key) in AES.key_size
        self.key = key
        self.bs = AES.block_size
        self.mode = mode

    def __repr__(self):
        return "AESCipher(key=%r, mode=%r)" % (self.key, self.mode)

    def encrypt(self, raw):
        """Encrypt using AES in CBC or ECB mode."""

        raw = self.pad(raw)
        iv = (Random.new().read(self.bs) if (self.mode == AES.MODE_CBC)
              else '')
        aes = AES.new(key=self.key, mode=self.mode, IV=iv)
        return b64encode(iv + aes.encrypt(raw))

    def decrypt(self, enc):
        """Decrypt using AES in CBC mode. Expects the IV at the front of the string."""

        enc = b64decode(enc)
        if self.mode == AES.MODE_CBC:
            iv = enc[:self.bs]
            enc = enc[self.bs:]
        else:
            iv = ''
        aes = AES.new(key=self.key, mode=self.mode, IV=iv)
        dec = aes.decrypt(enc)
        return self.unpad(dec)

    def unpad(self, text):
        """PKCS7 unpad"""

        last_byte = ord(text[-1:])
        if last_byte > self.bs:
            return text
        if text[-last_byte:] != chr(last_byte) * last_byte:
            return text
        return text[:-last_byte]

    def pad(self, text):
        """PKCS7 pad"""

        pad_num = self.bs - len(text) % self.bs
        return text + chr(pad_num) * pad_num

