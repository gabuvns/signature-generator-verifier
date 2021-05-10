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

def generatePublicAndPrivateKey():
    prime_bits = 512
    e = 65537
    p = getPrime(prime_bits)
    q = getPrime(prime_bits)

    while p == q:
        q = getPrime(prime_bits)

    n = p * q   # RSA modulus

    phi = (p - 1) * (q - 1) # Carmichael's totient

    d = libnum.invmod(e, phi)   # modular multiplicative inverse
    

if __name__ == '__main__':
    # For this section let's generate private and public keys :)
    prime_bits = 512
    e = 65537
    p = getPrime(prime_bits)
    q = getPrime(prime_bits)

    while p == q:
        q = getPrime(prime_bits)

    n = p * q   # RSA modulus

    phi = (p - 1) * (q - 1) # Carmichael's totient

    d = libnum.invmod(e, phi)   # modular multiplicative inverse

    file_obj = open(r"input.txt", "r")
    message = file_obj.readlines()
    file_obj.close()

    message = ''.join(message)
    
    hashed_message = hashlib.sha3_256(message.encode())
    print( "Hashed text: " +  hashed_message.hexdigest())
    print("Message read: ")
    print("%s\n" % message)
    
    encoded_bytes = base64.b64encode(hashed_message.hexdigest().encode('UTF-8'))
    # 
    int_b = int.from_bytes(encoded_bytes, 'big')

    print("b64: %s\n" % encoded_bytes)
    print("Int representation: %s\n" % int_b)
    #Gera chave publica    
    c = pow(int_b, e, n)
    print("Cipher-int: %s\n" % c)
    
    dc = pow(c, d, n)
    
    dc = [0] * len(c)
    # print(len(dc))
    for i in range(len(c)):
        dc[i] = pow(c[i], d, n)
        dc[i] = int.to_bytes(dc[i], 128, byteorder='big')
        print(dc[i])
        dc[i] = base64.b64decode(dc[i])
        dc[i] = dc[i].decode('utf-8')

    print("Deciphered-int: %s\n" % dc)
    dc = (dc).to_bytes((dc.bit_length() + 7) // 8, byteorder='big')
    print("Deciphered-b64: %s\n" % dc)

    encoded_str = base64.b64decode(dc + b'===')
    res = str(encoded_str, 'UTF-8')
    
    print("Deciphered text hashed: %s\n" % res)
    
    # finalMessage+=res
        
    
    # separatedMessage = []
    
    # messageCounter = 0;
    # finalMessage=""
    # auxMessage=""
    
    # for c in message:
            
    #     auxMessage+=c
    #     messageCounter+=1
    #     if messageCounter % 64 == 0 or messageCounter == len(message):
    #         separatedMessage.append(auxMessage)
    #         auxMessage=""
    # encryptMessage(privateKey, message);
    # for i in separatedMessage:
    #     print("BEGIN LOOP\n")
    #     print("MENSAGEM ANTES")
    #     print(i)
    #     encoded_bytes = base64.b64encode(i.encode('UTF-8'))
    #     int_b = int.from_bytes(encoded_bytes, 'big')
    
    #     print("b64: %s\n" % encoded_bytes)
    #     print("Int representation: %s\n" % int_b)
    
    #     c = pow(int_b, e, n)
    #     print("Cipher-int: %s\n" % c)
        
    #     dc = pow(c, d, n)
        
    #     print("Deciphered-int: %s\n" % dc)
    #     dc = (dc).to_bytes((dc.bit_length() + 7) // 8, byteorder='big')
    #     print("Deciphered-b64: %s\n" % dc)

    #     encoded_str = base64.b64decode(dc + b'===')
    #     res = str(encoded_str, 'UTF-8')
        
    #     print("Deciphered text: %s\n" % res)
    #     finalMessage+=res
        
    # print(finalMessage)   