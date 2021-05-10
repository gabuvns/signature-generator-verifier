import sys
import random
import hashlib  # hash
if sys.version_info < (3, 6):
    import sha3


def os2i(x: bytes) -> int:
    '''Converts an octet string to a nonnegative integer'''
    return int.from_bytes(x, byteorder='big')


def i2os(x: int, xlen: int) -> bytes:
    '''Converts int to octet string'''
    return x.to_bytes(xlen, byteorder='big')


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


def main():
    k = 1024 # tamanho da chave
    m = "ola mundo"
    m_encoded = m.encode()
    # m_bin = bin(m_encoded)

    r = i2os(random.randint(1, (2**1024-1)), 128)
    k0 = len(r)
    
    # print(m_int.bit_length())
    # print(len(m_encoded))
    while (len(m_encoded) < 125): # bytes - 3 bytes of format
        # print(m_bin.bit_length())
        m_encoded += b'0'

    m_formated = m_encoded + i2os(9, 3)
    print(m_formated)

    Gr = mgf1(r, 128)
    print(len(Gr))
    X = xor(Gr, m_formated)
    HX = mgf1(X, k0)
    Y = xor(r, HX)
    
    # print(X)
    # print(Y)
    # print(r)
    r = xor(Y, HX)
    # print(r)
    res = xor(X, Gr)
    print(res)      # formated bytes

    res_len = os2i(m_formated[125:128])
    print(res_len)  # message len

    res = res[:res_len]
    res = res.decode()
    print(res)      # message


main()