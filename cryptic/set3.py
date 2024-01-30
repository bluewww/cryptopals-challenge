# SPDX-License-Identifier: MIT
# Robert Balas <balasr@iis.ee.ethz.ch>

import secrets

from basic import (aes_cbc_decrypt, aes_cbc_encrypt, pkcs7_pad_with,
                   pkcs7_is_valid_padding, bxor, pkcs7_strip_padding)

# Challenge 17
# The CBC padding oracle
global_key = secrets.token_bytes(16)
global_iv = secrets.token_bytes(16)
pool = b"""MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93""".split(b'\n')


def aes_enc_random():
    return aes_cbc_encrypt(
        pkcs7_pad_with(bytearray(pool[secrets.randbelow(10)]), 16),
        global_key, global_iv), global_iv


def aes_dec_padding_oracle(ciphertext, iv):
    plaintext = aes_cbc_decrypt(ciphertext, global_key, iv)
    # print('dec =', plaintext)
    return pkcs7_is_valid_padding(plaintext, 16)


def aes_cbc_padding_attack(oracle, ciphertext, iv):
    """Classic CBC padding oracle attack"""
    AES_BS = 16
    # Brute force last byte of last encrypted block by modifying second to last
    # encrypted block such that the last byte is a valid padding of 0x1 (we
    # exclude other valid paddings). Move on to second to last byte by setting
    # the last byte to 0x2 to form another valid padding and so on.

    def attack_block(block):
        """Attack a single AES-CBC encrypted block"""
        # Decrypted ciphertext of block. Still needs to be xor'd with the
        # previous block to obtain the plaintext
        dct = bytearray(AES_BS)
        for off in range(1, AES_BS+1):
            prev_block = bytearray(AES_BS)
            for char in range(256):
                pad = off
                prev_block = bytearray(bxor(bytes([pad] * AES_BS), dct))
                prev_block[-off] = char
                if oracle(prev_block+block, iv):
                    if off == 1:
                        # Make sure this a 0x1 padding by modifying the second
                        # to last byte of the second to last block
                        prev_block[-2] = (~prev_block[-2]) & 0xff
                        if oracle(prev_block+block, iv):
                            dct[-off] = 0x1 ^ char
                            break
                    else:
                        dct[-off] = pad ^ char
                        break
        return dct

    for block in (ciphertext[k:k+AES_BS] for k in
                  range(len(ciphertext)-AES_BS, -1, -AES_BS)):
        pass

    prev = iv
    plaintext = bytearray()
    for block in (ciphertext[k:k+AES_BS] for k in
                  range(0, len(ciphertext), AES_BS)):
        dct = attack_block(block)
        plaintext += bxor(dct, prev)
        prev = block

    return plaintext


dec = aes_cbc_padding_attack(aes_dec_padding_oracle, *aes_enc_random())
assert pkcs7_strip_padding(dec, 16) in pool
print(dec)
