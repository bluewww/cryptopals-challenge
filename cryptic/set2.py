# SPDX-License-Identifier: MIT
# Robert Balas <balasr@iis.ee.ethz.ch>

# Challenge 9
# Implement PKCS#7 padding

import base64
import secrets

from Crypto.Cipher import AES

from basic import (aes_cbc_decrypt, aes_cbc_encrypt, aes_detect_ecb_block_mode,
                   aes_ecb_encrypt)


def pad_with_pkcs7(ba, align):
    diff = -len(ba) % align
    ba.extend(diff.to_bytes(1, 'big') * diff)
    return ba


block = b"YELLOW SUBMARINE"
print(pad_with_pkcs7(bytearray(block), 20))


# Challenge 10
# Implement CBC mode

with open('data/10.txt', 'rb') as f:
    ciphertext = base64.b64decode(
        bytearray([c for line in f for c in line.strip()]))
    aes_key = b'YELLOW SUBMARINE'
    cipher = AES.new(aes_key, AES.MODE_ECB)
    text = ciphertext

    # aes-cbc-enc
    enc = aes_cbc_encrypt(text, aes_key, b'0000000000000000')

    # aes-cbc-dec
    dec = aes_cbc_decrypt(text, aes_key, b'0000000000000000')

    print('Challenge 10')
    print('dec =', dec)


# Challenge 11
# An ECB/CBC detection oracle
random_key = secrets.token_bytes(16)


def encryption_oracle(text):
    cnt0 = 5 + secrets.randbelow(6)  # 5-10
    cnt1 = 5 + secrets.randbelow(6)   # 5-10'
    text = bytearray(secrets.token_bytes(cnt0) + text + secrets.token_bytes(cnt1))
    if secrets.randbelow(2) == 1:
        print('CBC')
        return aes_cbc_encrypt(pad_with_pkcs7(text, 16), random_key,
                               secrets.token_bytes(16))
    else:
        print('ECB')
        return aes_ecb_encrypt(pad_with_pkcs7(text, 16), random_key)


print('Challenge 11')
for _ in range(0, 16):
    if aes_detect_ecb_block_mode(encryption_oracle):
        print('ECB(?)')
    else:
        print('CBC(?)')
    print('')


# Challenge 12
# Byte-at-a-time ECB decryption (Simple)

global_key = secrets.token_bytes(16)


def aes_ecb_oracle(text):
    """aes128_ecb_encrypt(text || unknown-string, global-key)"""
    unknown = (b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
               b"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
               b"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
               b"YnkK")

    return aes_ecb_encrypt(
        pad_with_pkcs7(bytearray(text + base64.b64decode(unknown)), 16),
        global_key)


def aes_ecb_pad_attack(oracle):
    # discover the block cipher size
    blocksize = -1
    base = len(oracle(b''))
    for i in range(128):
        feed = b'A' * i
        new = len(oracle(feed))
        if new != base:
            blocksize = new - base
            break

    # check if ciphertext is really ecb encrypted
    if not aes_detect_ecb_block_mode(oracle):
        raise Exception('oracle does not seem to use ECB mode')

    shift = bytearray(b'A' * blocksize)
    for off in range(0, base, 16):
        for k in range(16):
            feed = b'A' * (blocksize - 1 - k)
            expected = oracle(feed)[off+0:off+blocksize]
            for i in range(256):
                plaintext = shift[off+k+1:off+k+blocksize] + i.to_bytes(1, 'big')
                if oracle(plaintext)[0:blocksize] == expected:
                    shift += i.to_bytes(1, 'big')
                    break
    return shift[blocksize:], blocksize


print('Challenge 12')
dec, blocksize = aes_ecb_pad_attack(aes_ecb_oracle)
print('blocksize =', blocksize)
print('dec =', dec)
