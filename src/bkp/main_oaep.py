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


def os2i(x: bytes) -> int:
    '''Converts an octet string to a nonnegative integer'''
    return int.from_bytes(x, byteorder='big')


def i2os(x: int, xlen: int) -> bytes:
    '''Converts int to octet string'''
    return x.to_bytes(xlen, byteorder='big')


def xor(a: bytes, b: bytes) -> bytes:
    '''XOR of byte arrays'''
    res = b''
    la = len(a)
    lb = len(b)
    
    for i in range(max(la, lb)):
        if i < la and i < lb:
            res += (a[i] ^ b[i]).to_bytes(1, byteorder='big')
        elif i < la:
            res += a[i].to_bytes(1, byteorder='big')
        else:
            break
    
    return res


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


def mgf1(seed: bytes, length: int, f_hash=hashlib.sha3_512) -> bytes:
    """Mask generation function."""
    counter = 0
    output = bytes()
    
    while len(output) < length:
        # C = str(counter)
        enc_seed = seed + i2os(counter, 4)
        output += f_hash(enc_seed).digest()
        counter += 1

    return output[:length]


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
    e = 65537
    prime_size = int(sys.argv[1])    # n = p*q

    # Gerando n??meros primos
    print("Gerando primos")
    p = getPrime(prime_size)
    q = getPrime(prime_size)
    
    while p == q:
        q = getPrime(prime_size)

    print("p: {}\nq: {}\n".format(p, q))

    n = p * q   # RSA modulus

    phi = (p - 1) * (q - 1) # Carmichael's totient

    d = libnum.invmod(e, phi)   # modular multiplicative inverse

    # Lendo mensagem
    file_obj = open(r"input.txt", "r")
    message = file_obj.readlines()
    file_obj.close()

    message = ''.join(message)
    m_encoded = message.encode()
    print("Message read:\n%s\n" % message)

    # Gera hash
    msg_hash = hashlib.sha3_256(message.encode())
    print("Hashed signature:\n%s\n" % msg_hash.hexdigest())
    
    # Codifica hash
    encoded_bytes = base64.b64encode(msg_hash.hexdigest().encode('UTF-8'))

    int_byte = int.from_bytes(encoded_bytes, 'big')     # cast para int

    # print("Message b64:\n%s\n" % encoded_bytes)
    # print("Int representation:\n%s\n" % int_byte)
    
    # Encripta
    c = pow(int_byte, e, n)
    print("Cipher-int:\n%s\n" % c)
    
    # Desencripta
    dc = pow(c, d, n)
    
    # print("Deciphered-int:\n%s\n" % dc)
    dc = (dc).to_bytes(bytes_needed(dc), byteorder='big') # cast para bytes
    # print("Deciphered-b64:\n%s\n" % dc)

    encoded_str = base64.b64decode(dc)
    res = str(encoded_str, 'UTF-8')
    
    print("Deciphered text hash:\n%s\n" % res)


    r = i2os(random.randint(1, (2**1024-1)), 128)
    k0 = len(r)
    
    # while (len(m_encoded) < 125): # bytes - 3 bytes of format
    #     # print(m_bin.bit_length())
    #     m_encoded += b'0'

    m_formated = m_encoded + i2os(9, 3)
    # print(m_formated)

    Gr = mgf1(r, 128)
    # print(len(Gr))
    X = xor(Gr, m_formated)
    HX = mgf1(X, k0)
    Y = xor(r, HX)
    
    # print(X)
    # print(Y)
    # print(r)
    r = xor(Y, HX)
    # print(r)
    res = xor(X, Gr)
    # print(res)      # formated bytes

    res_len = os2i(m_formated[125:128])
    # print(res_len)  # message len

    res = res[:res_len]
    res = res.decode()
    print(res)   