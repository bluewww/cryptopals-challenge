# SPDX-License-Identifier: MIT
# Robert Balas <balasr@iis.ee.ethz.ch>

# Challenge 9
# Implement PKCS#7 padding

def pad_with_pkcs7(ba, align):
    diff = -len(ba) % align
    ba.extend(diff.to_bytes(1, 'big') * diff)
    return ba


block = b"YELLOW SUBMARINE"
print(pad_with_pkcs7(bytearray(block), 20))


# Challenge 10
# Implement CBC mode
