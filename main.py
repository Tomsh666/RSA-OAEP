import math

from tools import generate_rsa_keys, message_generation
from related_messages import related_messages_attack
from RSA_OAEP import rsa_oaep

import secrets


def main():
    print("1.Related messages attack")
    print("2.RSA_OAEP")
    choice = input("Select an option:")
    if choice == "1":
        e = 2
        n, e, d = generate_rsa_keys(e)
        m = secrets.randbits(32)
        mu = math.floor(math.log2(n) / (e**2))
        c1 = message_generation(n, e, m, mu)
        c2 = message_generation(n, e, m, mu)
        print("n =", n)
        print("e =", e)
        print("d =", d)
        print("m =", m)
        print("c1 =", c1)
        print("c2 =", c2)

        tmp_m = related_messages_attack(n, c1, c2, e)
        if tmp_m == m:
            print("m =", tmp_m)
            print("Done")
        else:
            print("Smth went wrong")
    elif choice == "2":
        rsa_oaep()
    else:
        print("Wrong option")


if __name__ == '__main__':
    main()

