def os2ip(x: bytes) -> int:
    '''Converts an octet string to a nonnegative integer'''
    return int.from_bytes(x, byteorder='big')


def i2osp(x: int, xlen: int) -> bytes:
    '''Converts int to octet string'''
    return x.to_bytes(xlen, byteorder='big')


def sha1(m: bytes) -> bytes:
    '''SHA-1 hash function'''
    hasher = hashlib.sha1()
    hasher.update(m)
    return hasher.digest()


def mgf1(seed: bytes, mlen: int, f_hash: Callable = sha1) -> bytes:
    '''MGF1 mask generation function with SHA-1'''
    t = b''
    hlen = len(f_hash(b''))
    for c in range(0, ceil(mlen / hlen)):
        _c = i2osp(c, 4)
        t += f_hash(seed + _c)
    return t[:mlen]


def xor(data: bytes, mask: bytes) -> bytes:
    '''Byte-by-byte XOR of two byte arrays'''
    masked = b''
    ldata = len(data)
    lmask = len(mask)
    for i in range(max(ldata, lmask)):
        if i < ldata and i < lmask:
            masked += (data[i] ^ mask[i]).to_bytes(1, byteorder='big')
        elif i < ldata:
            masked += data[i].to_bytes(1, byteorder='big')
        else:
            break
    return masked


def oaep_encode(m: bytes, k: int, label: bytes = b'',
                f_hash: Callable = sha1, f_mgf: Callable = mgf1) -> bytes:
    '''EME-OAEP encoding'''
    mlen = len(m)
    lhash = f_hash(label)
    hlen = len(lhash)
    ps = b'\x00' * (k - mlen - 2 * hlen - 2)
    db = lhash + ps + b'\x01' + m
    seed = os.urandom(hlen)
    db_mask = f_mgf(seed, k - hlen - 1, f_hash)
    masked_db = xor(db, db_mask)
    seed_mask = f_mgf(masked_db, hlen, f_hash)
    masked_seed = xor(seed, seed_mask)
    return b'\x00' + masked_seed + masked_db


def oaep_decode(c: bytes, k: int, label: bytes = b'',
                f_hash: Callable = sha1, f_mgf: Callable = mgf1) -> bytes:
    '''EME-OAEP decoding'''
    clen = len(c)
    lhash = f_hash(label)
    hlen = len(lhash)
    _, masked_seed, masked_db = c[:1], c[1:1 + hlen], c[1 + hlen:]
    seed_mask = f_mgf(masked_db, hlen, f_hash)
    seed = xor(masked_seed, seed_mask)
    db_mask = f_mgf(seed, k - hlen - 1, f_hash)
    db = xor(masked_db, db_mask)
    _lhash = db[:hlen]
    assert lhash == _lhash
    i = hlen
    while i < len(db):
        if db[i] == 0:
            i += 1
            continue
        elif db[i] == 1:
            i += 1
            break
        else:
            raise Exception()
    m = db[i:]
    return m


def encrypt(m: int, public_key: Key) -> int:
    '''Encrypt an integer using RSA public key'''
    e, n = public_key
    return pow(m, e, n)


def encrypt_raw(m: bytes, public_key: Key) -> bytes:
    '''Encrypt a byte array without padding'''
    k = get_key_len(public_key)
    c = encrypt(os2ip(m), public_key)
    return i2osp(c, k)


def encrypt_oaep(m: bytes, public_key: Key) -> bytes:
    '''Encrypt a byte array with OAEP padding'''
    hlen = 20  # SHA-1 hash length
    k = get_key_len(public_key)
    assert len(m) <= k - hlen - 2
    return encrypt_raw(oaep_encode(m, k), public_key)


def decrypt(c: int, private_key: Key) -> int:
    '''Decrypt an integer using RSA private key'''
    d, n = private_key
    return pow(c, d, n)


def decrypt_raw(c: bytes, private_key: Key) -> bytes:
    '''Decrypt a cipher byte array without padding'''
    k = get_key_len(private_key)
    m = decrypt(os2ip(c), private_key)
    return i2osp(m, k)


def decrypt_oaep(c: bytes, private_key: Key) -> bytes:
    '''Decrypt a cipher byte array with OAEP padding'''
    k = get_key_len(private_key)
    hlen = 20  # SHA-1 hash length
    assert len(c) == k
    assert k >= 2 * hlen + 2
    return oaep_decode(decrypt_raw(c, private_key), k)