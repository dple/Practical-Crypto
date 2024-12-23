import os
import hashlib
import random
from Crypto.PublicKey import RSA

import functools


class RingSigs:

    def __init__(self, k, l: int = 1024) -> None:
        self.k = k
        self.l = l
        self.n = len(k)
        self.q = 1 << (l - 1)

    def sign(self, m: str, z: int):
        self._permut(m)
        s = [None] * self.n
        u = random.randint(0, self.q)
        c = v = self._E(u)

        first_range = list(range(z + 1, self.n))
        second_range = list(range(z))
        whole_range = first_range + second_range

        for i in whole_range:
            s[i] = random.randint(0, self.q)
            e = self._g(s[i], self.k[i].e, self.k[i].n)
            v = self._E(v ^ e)
            if (i + 1) % self.n == 0:
                c = v

        s[z] = self._g(v ^ u, self.k[z].d, self.k[z].n)
        return [c] + s

    def vrf(self, m: str, sig):
        self._permut(m)

        def _f(i):
            return self._g(sig[i + 1], self.k[i].e, self.k[i].n)

        y = map(_f, range(len(sig) - 1))
        y = list(y)

        def _g(x, i):
            return self._E(x ^ y[i])

        r = functools.reduce(_g, range(self.n), sig[0])
        return r == sig[0]

    def _permut(self, m):
        msg = m.encode("utf-8")
        self.p = int(hashlib.sha1(msg).hexdigest(), 16)

    def _E(self, x):
        msg = f"{x}{self.p}".encode("utf-8")
        return int(hashlib.sha1(msg).hexdigest(), 16)

    def _g(self, x, e, n):
        q, r = divmod(x, n)
        if ((q + 1) * n) <= ((1 << self.l) - 1):
            result = q * n + pow(r, e, n)
        else:
            result = x
        return result


if __name__ == '__main__':
    size = 5
    msg1, msg2 = "Hello", "World"


    def _rn(_):
        return RSA.generate(1024, os.urandom)


    key = map(_rn, range(size))

    key = list(key)

    r = RingSigs(key)

    for i in range(size):
        sig1 = r.sign(msg1, i)
        print(sig1)
        sig2 = r.sign(msg2, i)
        print(sig2)

        assert r.vrf(msg1, sig1) and r.vrf(msg2, sig2) and not r.vrf(msg1, sig2)
