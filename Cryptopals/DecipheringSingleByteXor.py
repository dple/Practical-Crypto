from SingleByteXor import single_byte_xor_cipher
from collections import Counter

"""
Single byte XOR cipher, known as 
"""

occurance_english = {
    'a': 8.2389258,    'b': 1.5051398,    'c': 2.8065007,    'd': 4.2904556,
    'e': 12.813865,    'f': 2.2476217,    'g': 2.0327458,    'h': 6.1476691,
    'i': 6.1476691,    'j': 0.1543474,    'k': 0.7787989,    'l': 4.0604477,
    'm': 2.4271893,    'n': 6.8084376,    'o': 7.5731132,    'p': 1.9459884,
    'q': 0.0958366,    'r': 6.0397268,    's': 6.3827211,    't': 9.1357551,
    'u': 2.7822893,    'v': 0.9866131,    'w': 2.3807842,    'x': 0.1513210,
    'y': 1.9913847,    'z': 0.0746517
}

dist_english = list(occurance_english.values())

def compute_fitting_quotient(text: bytes) -> float:
    counter = Counter(text)
    dist_text = []
    l = len(text)
    for c in occurance_english:
        dist_text.append((counter.get(ord(c), 0) * 100) / l)

    return sum([abs(a - b) for a, b in zip(dist_english, dist_text)]) / len(dist_text)

def deciphering_single_byte_xor(ciphertext: bytes):
    original_text, encryption_key, min_fq = None, None, None
    for k in range(256):
        # we generate the plain text using encryption key `k`
        _text = single_byte_xor_cipher(ciphertext, k)
        
        # we compute the fitting quotient for this decrypted plain text
        _fq = compute_fitting_quotient(_text)
        
        # if the fitting quotient of this generated plain text is lesser
        # than the minimum seen till now `min_fq` we update.
        if min_fq is None or _fq < min_fq:
            encryption_key, original_text, min_fq = k, _text, _fq

    # return the text and key that has the minimum fitting quotient
    return original_text, encryption_key


if __name__ == '__main__':
    msg = b'British troops entered Cuxhaven at 1400 on 6 May - from now on all radio traffic will cease - wishing you all the best. Lt Kunkel.'
    cipher = single_byte_xor_cipher(msg, 69)
    print("Single byte XOR cipher of ", msg, "is: ", cipher)
    
    pt, k = deciphering_single_byte_xor(cipher)    
    print("Plaintext is:", pt.decode("ASCII") + ", encrypted by the key:", k)
    
