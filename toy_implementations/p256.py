import os 
from math import gcd 

p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
a = -3
b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
G = (
    48439561293906451759052585252797914202762949526041747995844080717082404635286,
    36134250956749795798585127919587881956611106672985015071877198253568414405109
)
n = 115792089210356248762697446949407573529996955224135760342422259061068512044369
O = (0, 1)

def length(n):
        count = 0
        
        while n > 0:
            count += 1
            n >>= 1
        
        return count if count > 0 else 1

def mod(x):
    return x % p

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
        x = (x * x) % m 
    
    return res

def mod_inv_ct(x, m):
    """
        Assume: modulus m is prime 
        Compute modular inversion using the Little Fermat theorem: x^(m - 1) = 1 (mod m) 
        x^(-1) = x^(m - 2) (mod m)        
    """
    if gcd(x, m) != 1:  # check if x and m are co-prime
        raise ValueError("Does not exist a inverse!")

    return mod_pow(x, m - 2, m)

def mod_add(x, y):
    return mod(x + y)

def mod_sub(x, y):
    return mod(x - y)

def mod_mul(x, y):
    return mod(x*y)

def mod_neg(x):
    return p - mod(x)

def mod_inv(x):
    return mod_inv_ct(x, p)

def mod_rand():
    r = os.urandom(32)
    return mod(int.from_bytes(r, 'big'))

def pt_inv(P):
    x, y = P
    return mod(x), mod_neg(y)

def pt_dbl(P):
    # Dbl a EC point
    if P == O:
        return O
    
    # lambda = (3x^2 + a)/2y
    x, y = P
    t1 = mod_mul(x, x)
    t1 = mod_mul(3, x)
    t1 = mod_add(t1, a)
    t2 = mod_mul(2, y)
    t2 = mod_inv(t2)
    l = mod_mul(t1, t2)

    # dbl_x = lambda^2 - 2x; dbl_y = lambda(x - dbl_x) - y
    dbl_x = mod_mul(l, l)
    dbl_x = mod_sub(dbl_x, x)
    dbl_x = mod_sub(dbl_x, x)
    dbl_y = mod_sub(x, dbl_x)
    dbl_y = mod_mul(l, dbl_y)
    dbl_y = mod_sub(dbl_y, y)

    return dbl_x, dbl_y

def pt_add(P, Q):
    if P == O:
        return Q
    if Q == O:
        return P
    
    xP, yP = P
    xQ, yQ = Q

    # lambda = (yQ - yP)/(xQ - xP)    
    t1 = mod_sub(yQ, yP)    
    t2 = mod_sub(xQ, xP)
    t2 = mod_inv(t2)
    l = mod_mul(t1, t2)

    # add_x = lambda^2 - xP -xQ; add_y = lambda(xP - add_x) - yP
    add_x = mod_mul(l, l)
    add_x = mod_sub(add_x, xP)
    add_x = mod_sub(add_x, xQ)
    add_y = mod_sub(xP, add_x)
    add_y = mod_mul(l, add_y)
    add_y = mod_sub(add_y, yP)

    return add_x, add_y


def scalar_mult(d, P):
    # Regular right-to-left scalar multiplication 
    if d == 0:
        return O
    
    R0, R1 = O, O       # R1 returns the result 
    while d > 0:
        bit = d%2 
        R0, R1 = (R0, pt_add(R1, P)) if bit else (pt_add(R0, P), R1)
        P = pt_dbl(P)
        d >>= 1

    return R1

# Scalar multiplication due to Montgomery ladder 
def montgomery_ladder(d, P):
    if d == 0:
        return O
    
    R0, R1 = O, P
    for i in range(length(d), 0, -1):
        bit = (d >> (i - 1)) & 1        
        R0, R1 = (pt_add(R0, R1), pt_dbl(R1)) if bit else (pt_dbl(R0), pt_add(R0, R1))
    
    #assert R1 == pt_add(R0, P)    
    return R0

print(scalar_mult(17, G))
print(montgomery_ladder(17, G))
#x, y = G
#print(x)
#print(y)
#print(G)

