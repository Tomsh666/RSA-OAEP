from Crypto.Util.number import getPrime, GCD, inverse
from Crypto.Util import asn1
from Crypto.Hash import SHA256, MD5
import random

from pyasn1.type import univ
from pyasn1.codec.der import encoder


def generate_rsa_keys(e):
    p = getPrime(512)
    q = getPrime(512)
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


def xor_bytes(a, b):
    int_a = int.from_bytes(a, byteorder='big')
    int_b = int.from_bytes(b, byteorder='big')
    tmp = int_a ^ int_b
    return tmp.to_bytes((tmp.bit_length() + 7) // 8, byteorder='big')


def g_func(r, length):
    h = SHA256.new()
    h.update(r)
    return h.digest()[:length]


def h_func(x, length):
    h = MD5.new()
    h.update(x)
    return h.digest()[:length]


def add_asn1_header(n, e, encrypted_aes_key, ciphertext):
    rsa_oid = univ.ObjectIdentifier('1.2.840.113549.1.1.7')
    rsa_encoded_oid = encoder.encode(rsa_oid)
    aes_oid = univ.ObjectIdentifier('2.16.840.1.101.3.4.1.42')
    aes_encoded_oid = encoder.encode(aes_oid)

    asn1_structure = asn1.DerSequence([
        asn1.DerSetOf({
            asn1.DerSequence([
                asn1.DerOctetString(rsa_encoded_oid),
                asn1.DerSequence([
                    asn1.DerInteger(n),
                    asn1.DerInteger(e),
                ]),
                asn1.DerSequence([]),
                asn1.DerSequence([
                    asn1.DerInteger(encrypted_aes_key)
                ]),
            ]),
        }),
        asn1.DerSequence([
            asn1.DerOctetString(aes_encoded_oid),
            asn1.DerInteger(len(ciphertext)),
        ])
    ])
    return asn1_structure.encode()


def pars_asn1_header(asn_content):
    asn_seq1 = asn1.DerSequence()
    asn_seq1.decode(asn_content)
    asn_set = asn1.DerSetOf()
    asn_set.decode(asn_seq1[0])
    asn_seq2 = asn1.DerSequence()
    asn_seq2.decode(asn_set[0])
    encrypted_aes_key = asn1.DerSequence()
    encrypted_aes_key.decode(asn_seq2[3])
    return encrypted_aes_key[0]
