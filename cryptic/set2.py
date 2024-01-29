# SPDX-License-Identifier: MIT
# Robert Balas <balasr@iis.ee.ethz.ch>

# Challenge 9
# Implement PKCS#7 padding

import base64
import secrets

from Crypto.Cipher import AES

from basic import (aes_cbc_decrypt, aes_cbc_encrypt, aes_detect_ecb_block_mode,
                   aes_ecb_encrypt, aes_ecb_pad_attack, pad_with_pkcs7,
                   strip_padding)

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


print('Challenge 12')
dec, blocksize = aes_ecb_pad_attack(aes_ecb_oracle)
print('blocksize =', blocksize)
print('dec =', dec)


# Challenge 13
# ECB cut-and-pastte

# Challenge 14
# Byte-at-a-time ECB decryption (Harder)

random_prefix = secrets.token_bytes(secrets.randbelow(128))


def aes_ecb_oracle_harder(text):
    """aes128_ecb_encrypt(random-prefix || text || target-bytes, global-key)"""
    unknown = (b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
               b"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
               b"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
               b"YnkK")

    return aes_ecb_encrypt(
        pad_with_pkcs7(
            bytearray(random_prefix + text + base64.b64decode(unknown)), 16),
        global_key)


print('Challenge 14')
dec, blocksize = aes_ecb_pad_attack(aes_ecb_oracle_harder)
print('blocksize =', blocksize)
print('dec =', dec)


# Challenge 15
# PKCS#7 padding validation


print('Challenge 15')
print(strip_padding(bytearray(b'ICE ICE BABY\x04\x04\x04\x04'), 16))
print(strip_padding(pad_with_pkcs7(bytearray(b'YELLOW SUBMARINE'), 16),  16))


# Challenge 16
# CBC bitflipping attacks
