import sys
import random
import libnum   # mod
import Crypto
from Crypto.Util.number import *
import base64   # encode/decode
from math import log
import hashlib  # hash
if sys.version_info < (3, 6):
    import sha3

def bytes_needed(n):
    if n == 0:
        return 1
    return int(log(n, 256)) + 1

initial_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                  31, 37, 41, 43, 47, 53, 59, 61, 67,
                  71, 73, 79, 83, 89, 97, 101, 103,
                  107, 109, 113, 127, 131, 137, 139,
                  149, 151, 157, 163, 167, 173, 179,
                  181, 191, 193, 197, 199, 211, 223,
                  227, 229, 233, 239, 241, 251, 257,
                  263, 269, 271, 277, 281, 283, 293,
                  307, 311, 313, 317, 331, 337, 347, 349]


def getRandomNumber(n):
    '''Random number of n bits.'''
    return random.randrange(2**(n-1)+1, 2**n - 1)


def isMillerRabinPassed(candidate, iterations):
    '''Run Rabin Miller Primality check `iterations` times'''
    maxDivisionsByTwo = 0
    ec = candidate-1

    while ec % 2 == 0:
        ec >>= 1
        maxDivisionsByTwo += 1

    assert(2**maxDivisionsByTwo * ec == candidate-1)

    def _isComposite(round_tester):
        if pow(round_tester, ec, candidate) == 1:
            return False

        for i in range(maxDivisionsByTwo):
            if pow(round_tester, 2**i * ec, candidate) == candidate-1:
                return False
        return True

    for i in range(iterations):
        round_tester = random.randrange(2, candidate)
        if _isComposite(round_tester):
            return False

    return True


def getPrime(n):
    '''Generate a prime'''
    while True:
        prime_candidate = getRandomNumber(n)

        for divisor in initial_primes:
            if prime_candidate % divisor == 0 and divisor**2 <= prime_candidate:  # candidate is composite
                break  # not prime
            else:
                if isMillerRabinPassed(prime_candidate, 40):
                    return prime_candidate  # prime
                else:
                    break  # not prime


if __name__ == '__main__':
    message = "Dupla Eduardo e Carlinhos"
    prime_bits = 512
    e = 65537
    p = getPrime(prime_bits)
    q = getPrime(prime_bits)

    while p == q:
        q = getPrime(prime_bits)

    n = p * q   # RSA modulus

    phi = (p - 1) * (q - 1) # Carmichael's totient

    d = libnum.invmod(e, phi)   # modular multiplicative inverse

    # print(n.bit_length())
    # print ("Message=%s\np=%s\nq=%s\n\nd=%d\ne=%d\nN=%s\n\nPrivate key (d,n)\nPublic key (e,n)\n\ncipher=%s\ndecipher=%s" % (message,p,q,d,e,n,c,(long_to_bytes(res))))

    file_obj = open(r"input.txt", "r")
    message = file_obj.readlines()
    file_obj.close()

    message = ''.join(message)
    message = "Ola teste 123"
    # c = ''
    # for ch in message:
    #     m = ord(ch)
    #     # print('ch: ', ch)
    #     # print('m: ', m)
    #     c += str(pow(m, e, n)) + " "

    print("Message read: ")
    print("%s\n" % message)

    encoded_bytes = base64.b64encode(message.encode('UTF-8'))
    int_b = int.from_bytes(encoded_bytes, 'big')
    
    # info = [int_b[i:i+2] for i in range(0, len(int_b), 2)]

    print("b64: %s\n" % encoded_bytes)
    print("Int representation: %s\n" % int_b)

    # hash_sha3_512 = hashlib.new("sha3_512", message.encode())
    # print("HASH:\n{}".format(hash_sha3_512.hexdigest()))

    c = pow(int_b, e, n)
    
    print("Cipher-int: %s\n" % c)

    # m = int.from_bytes(message.encode(), byteorder='big', signed=False)
    # c = pow(m, e, n)    # Generating cipher text

    # c = base64.b64encode(c.encode())
    
    # file_obj = open(r"cipher_text.txt", "w")
    # file_obj.write(str(c))
    # file_obj.close()
    
    # print("Ciphered text: ")
    # print(long_to_bytes(c))

    # c = base64.b64decode(c).decode()

    # parts = c.split()
    # print(c)
    # print('\n')
    # print(parts)
    # res = ''
    # for part in parts:
    #     if part:
    #         ch = int(part)
    #         res += chr(pow(ch, d, n))

    # res = pow(c, d, n)  # Deciphering text

    dc = pow(c, d, n)
    
    print("Deciphered-int: %s\n" % dc)
    dc = (dc).to_bytes((dc.bit_length() + 7) // 8, byteorder='big')
    print("Deciphered-b64: %s\n" % dc)
    
    encoded_str = base64.b64decode(dc)
    res = str(encoded_str, 'UTF-8')

    file_obj = open(r"output.txt", "w")
    file_obj.writelines(res)
    file_obj.close()

    print("Deciphered text: %s\n" % res)

    # data = b'\x00\x00\x00\x00\x00'
    # info = [data[i:i+2] for i in range(0, len(data), 2)]
    # print(info)