# SPDX-License-Identifier: MIT
# Robert Balas <balasr@iis.ee.ethz.ch>

import base64
from collections import Counter

from Crypto.Cipher import AES

from basic import (ascii_letter_bytes, best_plaintext, best_plaintexts_sorted,
                   best_xor_key, bxor, ceildiv, keysize_heuristic,
                   transpose_text)

# Challenge 1
# Convert hex to base64
bstring = bytes.fromhex('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
print('Challenge 1')
print(bstring)
print(base64.b64encode(bstring))


# Challenge 2
# Fixed XOR
# Write a function that takes two equal-length buffers and produces their XOR combination.
tmp = bytes.fromhex('1c0111001f010100061a024b53535009181c')
other = bytes.fromhex('686974207468652062756c6c277320657965')

print('Challenge 2')
print(bxor(tmp, other))
print(bxor(tmp, other).hex())


# Challenge 3
# Single-byte XOR cipher

# Our approach is to measure the letter distribution of the decoded text and
# compare it with the letter distribution of the english language (oxford
# dictionary) using the total variation distance
secret = bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')


print('Challenge 3')
plaintexts = [bxor(secret, key * len(secret)) for key in ascii_letter_bytes]
dist, idx = best_plaintext(plaintexts)
print('Most likely plaintext is')
print(plaintexts[idx])
print('with distance', dist)


# Challenge 4
# Detect single-character XOR

# Same strategy, just more candidates


candidates = []
with open('data/4.txt', 'r') as f:
    keyspace = [x.to_bytes(1, 'big') for x in range(256)]
    for line in f:
        ciphertext = bytes.fromhex(line.strip())
        candidates.extend(
            [bxor(ciphertext, key * len(ciphertext))
             for key in keyspace])

print('Challenge4')
index, variation = best_plaintexts_sorted(candidates)[0]
print(variation, candidates[index])

# Challenge 5
# Implement repeating-key XOR

plaintext = b"""Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
key = b'ICE'


print('Challenge 5')
ciphertext = bxor(plaintext, key * ceildiv(len(plaintext), 3))
print(ciphertext.hex())


# Challenge 6
# Break repeating-key XOR
keysize = 2

with open('data/6.txt', 'rb') as f:
    base64_ciphertext = bytearray([c for line in f for c in line.strip()])
    ciphertext = base64.b64decode(base64_ciphertext)
    print('Challenge 6')
    keysizes = keysize_heuristic(ciphertext, 2, 40)
    best_keysize = keysizes[0][0]
    print('best keysize =', best_keysize)
    key = []
    for text in transpose_text(ciphertext, best_keysize):
        dist, single_key = best_xor_key(text)
        key.append(single_key)
    key = bytearray(key)
    print('key =', key)
    plaintext = bxor(ciphertext, key * ceildiv(len(ciphertext), best_keysize))
    print('plaintext =', plaintext)


# Challenge 7
# AES in ECB mode
with open('data/7.txt', 'rb') as f:
    ciphertext = base64.b64decode(
        bytearray([c for line in f for c in line.strip()]))
    aes_key = b'YELLOW SUBMARINE'
    cipher = AES.new(aes_key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    print('Challenge 7')
    print(plaintext)


# Challenge 8
# Detect AES in ECB mode

def ecb_score(ba, blocksize):
    blocks = [ba[i:i+blocksize] for i in range(0, len(ba), blocksize)]

    duplicates = Counter()
    for b in blocks:
        duplicates[b] += 1

    score = 0
    for k, v in duplicates.items():
        if v > 1:
            score += 1
    return score / len(blocks)


# Our idea is to count the number of repeating 16-byte blocks. The more it
# happens the worse the score.
with open('data/8.txt', 'r') as f:
    ciphertexts = list(map(bytes.fromhex, f.readlines()))
    scores = sorted(map(lambda x: (x[0], ecb_score(x[1], 16)),
                        enumerate(ciphertexts)),
                    key=lambda x: x[1],
                    reverse=True)
    best_idx, best_score = scores[0]
    print('Challenge 8')
    print('score =', best_score)
    print('ciphertext =', ciphertexts[best_idx])
