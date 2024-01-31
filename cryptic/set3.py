# SPDX-License-Identifier: MIT
# Robert Balas <balasr@iis.ee.ethz.ch>

import base64
import secrets

from basic import (aes_cbc_decrypt, aes_cbc_encrypt, aes_ctr_enc, bxor,
                   pkcs7_is_valid_padding, pkcs7_pad_with, pkcs7_strip_padding,
                   xor_single_key_attack)

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


print('Challenge 17')
dec = aes_cbc_padding_attack(aes_dec_padding_oracle, *aes_enc_random())
assert pkcs7_strip_padding(dec, 16) in pool
print(dec)


# Challenge 18
# Implement CTR, the stream cipher mode
ctr_plaintext = base64.b64decode(b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
ctr_key = b'YELLOW SUBMARINE'
ctr_nonce = (0).to_bytes(8, 'little')

print('Challenge 18')
enc = aes_ctr_enc(ctr_plaintext, ctr_key, ctr_nonce)
print(ctr_plaintext)
print('ciphertext =', enc)


# Challenge 19
# Break fixed-nonce CTR mode using substitutions

aes_key = secrets.token_bytes(16)
nonce = (0).to_bytes(8, 'little')
problem = map(base64.b64decode, b"""SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==
Q29taW5nIHdpdGggdml2aWQgZmFjZXM=
RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==
RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=
SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk
T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=
UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=
T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl
VG8gcGxlYXNlIGEgY29tcGFuaW9u
QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==
QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=
QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==
QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==
SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==
SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==
VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==
V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==
V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==
U2hlIHJvZGUgdG8gaGFycmllcnM/
VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=
QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=
VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=
V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=
SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==
U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==
U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=
VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==
QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu
SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=
VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs
WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=
SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0
SW4gdGhlIGNhc3VhbCBjb21lZHk7
SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=
VHJhbnNmb3JtZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=""".split(b'\n'))

ciphertexts = list(map(lambda pt: aes_ctr_enc(pt, aes_key, nonce), problem))
# attack all ciphertexts "horizontally" treating them as single xor encryption
# (works since they alls hare the same keystream)
keystream = bytearray(0)
for row in zip(*ciphertexts):
    dist, key = xor_single_key_attack(bytearray(row))
    keystream += bytes([key])
print('Challenge 19')
print('keystream =', keystream)

for ct in ciphertexts:
    print(bxor(ct, keystream))


# Challenge 20
# Break fixed-nonce CTR statistically
# same attack

with open('data/20.txt', 'rb') as f:
    aes_key = secrets.token_bytes(16)
    nonce = (0).to_bytes(8, 'little')
    plaintexts = [base64.b64decode(bytearray(line.strip())) for line in f]
    ciphertexts = list(map(lambda pt: aes_ctr_enc(pt, aes_key, nonce), plaintexts))

    keystream = bytearray(0)
    for row in zip(*ciphertexts):
        dist, key = xor_single_key_attack(bytearray(row))
        keystream += bytes([key])

    print('Challenge 20')
    print('keystream =', keystream)
    for ct in ciphertexts:
        print(bxor(ct, keystream))
