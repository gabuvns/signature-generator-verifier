import sys
import random
import libnum
import Crypto
import base64
from math import log
from Crypto.Util.number import *

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
    
    c = ''
    for ch in message:
        m = ord(ch)
        # print('ch: ', ch)
        # print('m: ', m)
        c += str(pow(m, e, n)) + " "

    print("Message read: ")
    print(message)

    # m = int.from_bytes(message.encode(), byteorder='big', signed=False)
    # c = pow(m, e, n)    # Generating cipher text

    c = base64.b64encode(c.encode())
    
    file_obj = open(r"cipher_text.txt", "w")
    file_obj.write(str(c))
    file_obj.close()
    
    # print("Ciphered text: ")
    # print(long_to_bytes(c))

    c = base64.b64decode(c).decode()

    parts = c.split()
    # print(c)
    # print('\n')
    # print(parts)
    res = ''
    for part in parts:
        if part:
            ch = int(part)
            res += chr(pow(ch, d, n))

    # res = pow(c, d, n)  # Deciphering text
    
    file_obj = open(r"output.txt", "w")
    file_obj.writelines(res)
    file_obj.close()

    print("Deciphered text: ")
    print(res)