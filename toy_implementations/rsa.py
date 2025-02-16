import os 
from math import gcd

def mod_inv(x, m):
    # Invert an integer x modulo m using extended Euclidean algorithm

    if m == 1:
        return 0
    
    if gcd(x, m) != 1:      # check if x and m are co-prime
        raise ValueError("Does not exist an inverse!")
    
    oldr, r = x, m
    olds, s = 1, 0
    oldt, t = 0, 1

    while r > 0:
        q = oldr // r
        oldr, r = r, (oldr - q*r)
        olds, s = s, (olds - q*s)
        oldt, t = t, (oldt - q*t)

    return olds % m

def mod_pow(x, y, m):
    # Calculate x^y %m 
    if m == 1:
        return 0

    if y == 0:
        return 1
    
    # using right-to-left binary exp algo
    res = 1
    x = x % m
    while y > 0:
        if y % 2 == 1:
            res = (res * x) % m
        y >>= 1
        x *=x
    
    return res


print(mod_inv(17, 43))