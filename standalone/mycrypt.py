from Crypto.Cipher import ARC4
from Crypto.Cipher import AES
from Crypto.Cipher import DES
import hashlib

def myrc4(key, m):
    cipher = ARC4.new(key)
    return cipher.encrypt(m)


def mydes_encrypt(key, m):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(m)


def mydes_decrypt(key, c):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.decrypt(c)


def myaes_encrypt(key, m):
    bs = AES.block_size
    pad = lambda s: s + (bs - len(s) % bs) * chr(bs - len(s) % bs)
    cipher = AES.new(key, AES.MODE_ECB)
    result = cipher.encrypt(pad(m))
    return result


def myaes_decrypt(key, c):
    # cryptos = AES.new(key, AES.MODE_CBC, iv=iv)
    cryptos = AES.new(key, AES.MODE_ECB)
    meg = cryptos.decrypt(c)
    return meg[:-ord(meg[-1])]


def mytea_encrypt(v, k):
    v0 = v[0]
    v1 = v[1]
    x = 0
    delta = 0x9E3779B9
    k0 = k[0]
    k1 = k[1]
    k2 = k[2]
    k3 = k[3]
    for i in range(32):
        x += delta
        x = x & 0xFFFFFFFF
        v0 += ((v1 << 4) + k0) ^ (v1 + x) ^ ((v1 >> 5) + k1)
        v0 = v0 & 0xFFFFFFFF
        v1 += ((v0 << 4) + k2) ^ (v0 + x) ^ ((v0 >> 5) + k3)
        v1 = v1 & 0xFFFFFFFF
    v[0] = v0
    v[1] = v1
    return v


def mytea_decrypt(v, k):
    v0 = v[0]
    v1 = v[1]
    x = 0xC6EF3720
    delta = 0x9E3779B9
    k0 = k[0]
    k1 = k[1]
    k2 = k[2]
    k3 = k[3]
    for i in range(32):
        v1 -= ((v0 << 4) + k2) ^ (v0 + x) ^ ((v0 >> 5) + k3)
        v1 = v1 & 0xFFFFFFFF
        v0 -= ((v1 << 4) + k0) ^ (v1 + x) ^ ((v1 >> 5) + k1)
        v0 = v0 & 0xFFFFFFFF
        x -= delta
        x = x & 0xFFFFFFFF
    v[0] = v0
    v[1] = v1
    return v


def shift(z, y, x, k, p, e):
    return (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((x ^ y) + (k[(p & 3) ^ e] ^ z))


def myxxtea_encrypt(v, k):
    delta = 0x9E3779B9
    n = len(v)
    rounds = 6 + 52 / n
    x = 0
    z = v[n - 1]
    for i in range(rounds):
        x = (x + delta) & 0xFFFFFFFF
        e = (x >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            v[p] = (v[p] + shift(z, y, x, k, p, e)) & 0xFFFFFFFF
            z = v[p]
        p += 1
        y = v[0]
        v[n - 1] = (v[n - 1] + shift(z, y, x, k, p, e)) & 0xFFFFFFFF
        z = v[n - 1]
    return v


def myxxtea_decrypt(v, k):
    delta = 0x9E3779B9
    n = len(v)
    rounds = 6 + 52 / n
    x = (rounds * delta) & 0xFFFFFFFF
    y = v[0]
    for i in range(rounds):
        e = (x >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            v[p] = (v[p] - shift(z, y, x, k, p, e)) & 0xFFFFFFFF
            y = v[p]
        p -= 1
        z = v[n - 1]
        v[0] = (v[0] - shift(z, y, x, k, p, e)) & 0xFFFFFFFF
        y = v[0]
        x = (x - delta) & 0xFFFFFFFF
    return v


def myxtea_encrypt(rounds, v, k):
    v0 = v[0]
    v1 = v[1]
    x = 0
    delta = 0x9E3779B9
    for i in range(rounds):
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (x + k[x & 3])
        v0 = v0 & 0xFFFFFFFF
        x += delta
        x = x & 0xFFFFFFFF
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (x + k[(x >> 11) & 3])
        v1 = v1 & 0xFFFFFFFF
    v[0] = v0
    v[1] = v1
    return v


def myxtea_decrypt(rounds, v, k):
    v0 = v[0]
    v1 = v[1]
    delta = 0x9E3779B9
    x = delta * rounds
    for i in range(rounds):
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (x + k[(x >> 11) & 3])
        v1 = v1 & 0xFFFFFFFF
        x -= delta
        x = x & 0xFFFFFFFF
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (x + k[x & 3])
        v0 = v0 & 0xFFFFFFFF
    v[0] = v0
    v[1] = v1
    return v

def mymd5(s):
    m2 = hashlib.md5()
    m2.update(s)
    return m2.digest()


if __name__ == '__main__':
    key = '12345678'
    m = '12345678'
    assert len(key) == 8
    assert len(m) % 8 == 0
    c = mydes_encrypt(key, m)
    m2 = mydes_decrypt(key, c)
    assert m == m2

    m3 = '1234567887654321'
    key2 = '1234567887654321'
    c2 = myaes_encrypt(key2, m3)
    m4 = myaes_decrypt(key2, c2)
    assert m4 == m3
