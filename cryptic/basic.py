# SPDX-License-Identifier: MIT
# Robert Balas <balasr@iis.ee.ethz.ch>
import itertools
import string
from collections import Counter

__all__ = ['ascii_letter_bytes', 'en_char_distribution']

ascii_letter_bytes = [char.encode('utf-8') for char in string.ascii_letters]
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


def bxor(ba1, ba2):
    return bytes([x ^ y for x, y in zip(ba1, ba2)])


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


def best_xor_key(ciphertext):
    keyspace = [x.to_bytes(1, 'big') for x in range(256)]
    candidates = [bxor(ciphertext, key * len(ciphertext))
                  for key in keyspace]
    return best_plaintext(candidates)


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


def ceildiv(a, b):
    return ((a - 1) // b) + 1