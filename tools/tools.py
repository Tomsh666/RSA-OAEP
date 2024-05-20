from Crypto.Util.number import getPrime, GCD, inverse
import random


def generate_rsa_keys(e):
    p = getPrime(256)
    q = getPrime(256)
    n = p * q
    phi = (p - 1) * (q - 1)
    while e < phi:
        if GCD(e, phi) == 1:
            break
        else:
            e += 1
    d = inverse(e, phi)
    return n, e, d


def rsa_encrypt(n, e, m):
    c = pow(m, e, n)
    return c


def message_generation(n, e, m, mu):
    r = random.randint(0, 2 ** mu - 1)
    m1 = pow(2, mu) * m + r
    c = rsa_encrypt(n, e, m1)
    return c
