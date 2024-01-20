# SPDX-License-Identifier: MIT
# Robert Balas <balasr@iis.ee.ethz.ch>

import base64
import string
from collections import Counter
import itertools
from Crypto.Cipher import AES

# Challenge 1
# Convert hex to base64
bstring = bytes.fromhex('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
print('Challenge 1')
print(bstring)
print(base64.b64encode(bstring))

# Challenge 2
# Fixed XOR
# Write a function that takes two equal-length buffers and produces their XOR combination.


def bxor(ba1, ba2):
    return bytes([x ^ y for x, y in zip(ba1, ba2)])


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
ascii_letter_bytes = [char.encode('utf-8') for char in string.ascii_letters]
secret = bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')

en_char_distribution = Counter({
    b'e': 0.111607, b'm': 0.030129,
    b'a': 0.084966, b'h': 0.030034,
    b'r': 0.075809, b'g': 0.024705,
    b'i': 0.075448, b'b': 0.020720,
    b'o': 0.071635, b'f': 0.018121,
    b't': 0.069509, b'y': 0.017779,
    b'n': 0.066544, b'w': 0.012899,
    b's': 0.057351, b'k': 0.011016,
    b'l': 0.054893, b'v': 0.010074,
    b'c': 0.045388, b'x': 0.002902,
    b'u': 0.036308, b'z': 0.002722,
    b'd': 0.033844, b'j': 0.001965,
    b'p': 0.031671, b'q': 0.001962})


def total_variation_dist(dist1, dist2):
    # union of dist1 and dist2 keys so we can iterate easily over all elements
    union = Counter()
    for counter in [dist1, dist2]:
        union |= counter

    dist = 0
    for k in union.keys():
        dist += abs(dist1[k] - dist2[k])

    return dist/2


def char_distribution(plaintext):
    counter = Counter()
    for char in plaintext:
        counter[char.to_bytes(1, 'big')] += 1
    total = sum(counter.values(), 0.0)
    for c in counter:
        counter[c] /= total
    return counter


def best_plaintext(plaintexts):
    distributions = []
    for plaintext in plaintexts:
        distributions.append(char_distribution(plaintext))

    min_dist = 1000
    min_dist_idx = -1
    for i, d in enumerate(distributions):
        en_dist = total_variation_dist(en_char_distribution, d)
        if en_dist < min_dist:
            min_dist = en_dist
            min_dist_idx = i

    return min_dist, min_dist_idx


def best_xor_key(ciphertext):
    keyspace = [x.to_bytes(1, 'big') for x in range(256)]
    candidates = [bxor(ciphertext, key * len(ciphertext))
                  for key in keyspace]
    return best_plaintext(candidates)


print('Challenge 3')
plaintexts = [bxor(secret, key * len(secret)) for key in ascii_letter_bytes]
dist, idx = best_plaintext(plaintexts)
print('Most likely plaintext is')
print(plaintexts[idx])
print('with distance', dist)


# Challenge 4
# Detect single-character XOR

# Same strategy, just more candidates

def best_plaintexts_sorted(plaintexts):
    distributions = []
    for plaintext in plaintexts:
        distributions.append(char_distribution(plaintext))

    def dist(d):
        index, distribution = d
        return index, total_variation_dist(en_char_distribution, distribution)

    def sortkey(v):
        index, variation = v
        return variation

    variations = map(dist, enumerate(distributions))
    return sorted(variations, key=sortkey)


candidates = []
with open('4.txt', 'r') as f:
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


def ceildiv(a, b):
    return ((a - 1) // b) + 1


print('Challenge 5')
ciphertext = bxor(plaintext, key * ceildiv(len(plaintext), 3))
print(ciphertext.hex())


# Challenge 6
# Break repeating-key XOR
keysize = 2


def hamming_dist(ba1, ba2):
    dist = 0
    for b1, b2 in zip(ba1, ba2):
        d = b1 ^ b2
        while d:
            dist += 1
            d &= d - 1
    return dist


def keysize_heuristic(ba, low, high):

    def weight(n):
        groups = [(ba[i:i+n], ba[i+n:i+2*n]) for i in range(0, len(ba)-n, n)]
        dist = 0
        for x, y in groups:
            # normalize by keysize and number of samples
            dist += (hamming_dist(x, y) / n / len(groups))
        return n, dist

    key_sizes = map(weight, range(low, high))

    def sortkey(n):
        index, dist = n
        return dist

    return sorted(key_sizes, key=sortkey)


def transpose_text(text, size):
    chunks = [text[i:i+size] for i in range(0, len(text), size)]
    return [bytearray(x) for x in itertools.zip_longest(*chunks, fillvalue=0)]


with open('6.txt', 'rb') as f:
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
with open('7.txt', 'rb') as f:
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
with open('8.txt', 'r') as f:
    ciphertexts = list(map(bytes.fromhex, f.readlines()))
    scores = sorted(map(lambda x: (x[0], ecb_score(x[1], 16)),
                        enumerate(ciphertexts)),
                    key=lambda x: x[1],
                    reverse=True)
    best_idx, best_score = scores[0]
    print('Challenge 8')
    print('score =', best_score)
    print('ciphertext =', ciphertexts[best_idx])
