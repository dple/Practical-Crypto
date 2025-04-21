"""
Implementation of polynomial ring Zq[x]/<f(x)>, where
- f(x): monic irreducible polynomial of degree d, e.g., a cyclotomic polynomial f(x) = x^d + 1
- d is a power of 2, d = 2^n
- q coefficient modulus, q are not required a prime
"""

import numpy as np
from numpy.polynomial import polynomial as P

def polymod(A, q, poly_mod):
    return np.floor(P.polydiv(A, poly_mod)[1]).astype(np.int64) % q

def polyadd(A, B, q, poly_mod):
    """ Perform addition of two polynomials a, b in ring Zq[x]/<poly_mod>
        a, b: are input polynomials
        q: coefficient modulus
        poly_mod: polynomial modulus
    """
    C = P.polyadd(A, B)
    return np.floor(P.polydiv(C, poly_mod)[1]).astype(np.int64) % q

def polymul(A, B, q, poly_mod):
    """" Perform addition of two polynomials a, b in ring Zq[x]/<poly_mod>
         a, b: are input polynomials
         q: coefficient modulus
         poly_mod: polynomial modulus
    """
    C = P.polymul(A, B)
    return np.floor(P.polydiv(C, poly_mod)[1]).astype(np.int64) % q


def bin_poly_gen(d):
    """ Generate a random polynomial of degree n - 1 in Z2[X]

    Parameters:
        d: d - 1 is degree of polynomial
    """
    return np.random.randint(0, 2, d).astype(np.int64)


def int_poly_gen(d, q):
    """
    Generate a random polynomial of degree n - 1 in Zq[X]

    Parameters:
        d: d - 1 is degree of polynomial
        q: coefficient modulus
    """
    return np.random.randint(0, q, d).astype(np.int64) % q

def normal_poly_gen(d, q, mean=0, std=2):
    """
    Generates a polynomial in Zq[X], where coeffecients drawn from a normal distribution

    Parameters
        mean: mean of the distribution
        std: standard deviation of the distribution

    By default: mean = 0 and standard deviation = 2
    """
    return np.random.normal(mean, std, d).astype(np.int64) %q
