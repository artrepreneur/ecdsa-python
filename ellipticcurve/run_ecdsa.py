import sys
from ellipticcurve.ecdsa import Ecdsa
from ellipticcurve.privateKey import PrivateKey


def main():
    message = sys.argv[1]
    blinded_private_key = PrivateKey.fromString(sys.argv[2])
    k = int(sys.argv[3])

    signature = Ecdsa.signBlind(message, blinded_private_key, k, chain='BTC')
    print(signature)

if __name__ == "__main__":
    main()
