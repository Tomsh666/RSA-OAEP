from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

from tools import add_asn1_header, xor_bytes
from tools import g_func, h_func


def encrypt(file, e, n, aes_key):
    output_file = "encrypted_file.bin"
    with open(file, 'rb') as f:
        data = f.read()
    aes_encrypted_data = aes_encrypt(aes_key, data)
    encrypted_aes_key = rsa_oaep(aes_key, e, n)
    header = add_asn1_header(n, e, encrypted_aes_key, aes_encrypted_data)
    with open(output_file, 'wb') as f:
        f.write(header)
        f.write(aes_encrypted_data)


def aes_encrypt(key, data):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))
    return iv + encrypted_data


def rsa_oaep(m, e, n):
    k = len(m)
    k0 = k//4
    k1 = k0
    padded_m = m + b'\x00' * k1
    r = get_random_bytes(k0)
    X = xor_bytes(padded_m, g_func(r, k-k0))
    Y = xor_bytes(r, h_func(X, k0))
    tmp_m = X + Y
    return pow(int.from_bytes(tmp_m, byteorder='big'), e, n)









