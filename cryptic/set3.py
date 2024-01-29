# SPDX-License-Identifier: MIT
# Robert Balas <balasr@iis.ee.ethz.ch>

# Challenge 17
# The CBC padding oracle

import secrets

from basic import (aes_cbc_decrypt, aes_cbc_encrypt, pkcs7_pad_with,
                   pkcs7_is_valid_padding)

global_key = secrets.token_bytes(16)
global_iv = secrets.token_bytes(16)


def aes_enc_random():
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
    return aes_cbc_encrypt(
        pkcs7_pad_with(bytearray(pool[secrets.randbelow(10)]), 16),
        global_key, global_iv), global_iv


def aes_dec_padding_oracle(ciphertext, iv):
    plaintext = aes_cbc_decrypt(ciphertext, global_key, iv)
    return pkcs7_is_valid_padding(plaintext, 16)


print(aes_enc_random())
print(aes_dec_padding_oracle(*aes_enc_random()))
