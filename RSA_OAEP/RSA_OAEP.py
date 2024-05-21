from .encrypt import encrypt
from .decrypt import decrypt
from tools import generate_rsa_keys
from Crypto.Random import get_random_bytes


def rsa_oaep():
    e = 665536
    n, e, d = generate_rsa_keys(e)
    while True:
        print("1.Encrypt")
        print("2.Decrypt")
        choice = input("\nSelect an option:")
        if choice == "1":
            file_name = "plain_text.txt"
            aes_key = get_random_bytes(32)
            encrypt(file_name, e, n, aes_key)
            print("Done")
        elif choice == "2":
            file_name = "encrypted_file.bin"
            decrypt(file_name, d, n)
            print("Done")
        else:
            print("Wrong option")

