from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from tools import pars_asn1_header, xor_bytes
from tools import g_func, h_func


def decrypt(cipher_file, d, n):
    k = 32
    k0 = k // 4
    k1 = k0
    with open(cipher_file, 'rb') as file:
        asn_len = file.read(4)
        asn_len = int.from_bytes(asn_len[2:], byteorder='big')
    with open(cipher_file, 'rb') as file:
        asn_content = file.read(4 + asn_len)
        iv = file.read(AES.block_size)
        ciphertext = file.read()
    encrypted_aes_key = pars_asn1_header(asn_content)
    m = pow(encrypted_aes_key, d, n)
    num_bytes = (m.bit_length() + 7) // 8
    m = m.to_bytes(num_bytes, byteorder='big')
    X = m[:k+k0]
    Y = m[k+k0:]
    r = xor_bytes(Y, h_func(X, k0))
    padded_m = xor_bytes(X, g_func(r, k-k0))
    m = padded_m[:-k1]
    if padded_m[-k1:] != b'\x00' * k1:
        raise ValueError("Wrong ciphertext")
    aes_key = m
    output_file = "decrypted_file.bin"
    decrypted_data = aes_decrypt(aes_key, iv, ciphertext)
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)


def aes_decrypt(key, iv, data):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(data), AES.block_size)
    return decrypted_data



