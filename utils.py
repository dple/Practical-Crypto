from random import randint
import numpy as np

def powmod(a, b, mod):
    """
    Calculate modulo exponentiation using right-to-left binary implementation
    Given a, b, and n, return a^b mod m
    """
    if mod == 1:
        return
    A = a % mod
    if A == 1:
        return 1

    r = 1
    while b > 0:
        if b % 2 == 1:
            r = (r * A) % mod
        A = (A * A) % mod
        b //= 2
    return r

def isPrime(p):
    """  Checking if p is a prime by using the observation that: p = 6k +/- 1 if p > 3 """
    if p <= 3:
        return p > 1
    if p % 2 == 0 or p % 3 == 0:
        return False

    sqrt = np.sqrt(p).astype(np.int64) + 1    
    for i in filter(lambda x: x % 6 == 1 or x % 6 == 5, range(5, sqrt)):
        if p % i == 0:
            return False

    return True


def isFermatPrime(p, iter):
    """
    Checking if p is a probably prime. The simplest method is Fermat primality test.
    Given an integer a, coprime to p, if
        a^{p - 1} = 1 mod p, then p is prime
    """
    for i in range(iter):
        a = randint(2, p - 1)
        if powmod(a, p - 1, p) != 1:
            return False
    return True             # probably prime


def isMillerRabinPrime(p, iter):
    """ Checking if p is a probably prime using Miller-Rabin primality test """
    if p < 4:
        return p > 1

    if p % 2 == 0:
        return False

    # now n is odd > 3
    s = 0
    d = p - 1
    # p = 2^s * d where d is odd
    while d % 2 == 0:
        s += 1
        d //= 2

    for i in range(iter):
        a = randint(2, p - 1)
        x = (a**d) % p
        if x == 1: continue
        for j in range(s):
            if x == p - 1: break
            x = (x ** 2) % p
        else:
            return False
    return True

def nextPrime(n):
    """ Calculate a prime p that is bigger than n using the fact that p = 6k +/- 1 """

    if n <= 0:
        return 2
    elif n < 3:
        return n + 1

    if n % 6 == 0:
        if isPrime(n + 1):
            return n + 1
        else:
            p = n + 5

    elif n % 6 == 5:
        if isPrime(n + 2):
            return n + 2
        else:
            p = n + 6
    else:
        p = n + (5 - (n % 6))

    while not isPrime(p):
        if isPrime(p + 2):
            return p + 2
        p += 6
    return p

def getPrime(b):
    """ Return a prime with b bits  """
    n = randint(2**(b - 1), 2**b)

    return nextPrime(n)

def getShophieGermainPrime(b):
    """
    Find a Sophie Germain prime with b bits. p is Sophie Germain prime if:
    - p is prime
    - 2*p + 1 is prime

    """
    p = getPrime(b - 1)
    sp = 2*p + 1

    while not isPrime(sp):
        p = getPrime(b - 1)
        sp = 2*p + 1
    return p

def genSafePrime(b):
    """
    Find a safe prime with b bits. p is a safe prime if:
    - p is prime
    - p // 2 is prime
    """
    p = getPrime(b - 1)
    sp = 2*p + 1

    while not isPrime(sp):
        p = getPrime(b - 1)
        sp = 2*p + 1
    return sp

def factor(n):
    """  Factorize an integer n  """
    p = 2
    factors = []
    while n != 1:
        while n % p == 0:
            factors.append(p)
            n /= p
        p = nextPrime(p)
    return factors


def tests():
    n = randint(2, 100000)
    b = randint(2, 63)      

    print("Factors of {} is {}".format(n, factor(n)))
    print("{} raise to power {} mod {} is {}:".format(2, n - 1, n, powmod(2, n - 1, n)))

    if isFermatPrime(n, 16):
        print("{} is a Fermat prime".format(n))
    if isMillerRabinPrime(n, 5):
        print("{} is a Miller-Rabin prime".format(n))
    if isPrime(n):
        print("{} is a prime".format(n))
    else:
        print("{} is not a prime".format(n))

    p = nextPrime(n)
    assert isPrime(p), "p is not a prime"
    print("The next prime after {} is {}".format(n, p))

    p = getPrime(b + 1)
    assert isPrime(p), "p is not a prime"
    print("{} is a prime with {} bits".format(p, b))

    p = getShophieGermainPrime(b + 1)
    assert isPrime(p), "p is not a Sophie Germain prime"
    print("{} is a Shophie Germain prime with {} bits".format(p, b))

    p = genSafePrime(b + 1)
    assert isPrime(p), "p is not a safe prime"
    print("{} is a safe prime with {} bits".format(p, b))


if __name__ == '__main__':
    tests()
