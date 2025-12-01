import hashlib
import random
import os
import numpy as np
from PIL import Image

import PLShandler as plsh

PLS = []

# open cover image for encoding (unchanged)
img = Image.open(r"images/in1.png")
[row, col] = img.size


def DataListInBit(data):
    """
    Accepts `data` as either bytes or str.
    Returns list of 8-bit strings for each byte and the raw bytes.
    """
    if isinstance(data, str):
        data_bytes = data.encode('latin-1')  # keep 1:1 byte mapping
    else:
        data_bytes = data  # assume bytes

    dataBits = [format(c, '08b') for c in data_bytes]
    return dataBits, data_bytes


def PLSgen(row, col, lenEncodedBytes):
    """
    Generate pixel locator sequence for lenEncodedBytes bytes.
    Saves the first lenEncodedBytes*3 entries to PLS and writes pls.txt
    """
    new = list(range(row * col))
    # Fisher-Yates shuffle
    for i in range(len(new) - 1, 0, -1):
        j = random.randint(0, i)
        new[i], new[j] = new[j], new[i]

    # pick first lenEncodedBytes * 3 positions
    sel = new[:lenEncodedBytes * 3]
    # store into global PLS (as ints)
    PLS.clear()
    PLS.extend(sel)
    pixelLocaterSequence = np.array(PLS, dtype=int)
    np.savetxt("pls.txt", pixelLocaterSequence, delimiter="\t", fmt='%d')


def LsbEncoding(encodedText):
    """
    encodedText: bytes or str. Embeds it into images/in1.png -> images/out1.png
    """
    dataBits, data_bytes = DataListInBit(encodedText)
    n_bytes = len(data_bytes)

    # generate PLS
    PLSgen(row, col, n_bytes)

    dr = 0
    for i in range(0, n_bytes * 3, 3):
        dc = 0
        for j in range(0, 3):
            rr = PLS[i + j] // col
            rc = PLS[i + j] % col
            rgb = img.getpixel((rr, rc))
            value = []
            # write up to 8 bits from dataBits[dr]
            for k in rgb:
                if dc >= 8:
                    break
                bit = dataBits[dr][dc]
                # set LSB of k to match bit
                if (k % 2 == 0 and bit == '1'):
                    # make it odd
                    if k == 0:
                        k += 1
                    else:
                        k -= 1
                if (k % 2 == 1 and bit == '0'):
                    k -= 1
                value.append(k)
                dc += 1

            # if less than 3 channels were modified (possible when dc hits 8), keep remaining channels same
            while len(value) < 3:
                value.append(rgb[len(value)])

            newrgb = (value[0], value[1], value[2])
            img.putpixel((rr, rc), newrgb)
        dr += 1

    img.save("images/out1.png")

    # encrypt pls file (positions) this preserves the PLS for decoding
    plsPassword = input("Insert Password for pls encyption :")
    key = hashlib.sha256(plsPassword.encode()).digest()
    plsh.encrypt_file(key, 'pls.txt')


def LsbDecoding():
    """
    Decrypt pls, read positions, extract bits and return message as latin-1 string
    (preserves raw byte values so downstream code can decode or treat as bytes).
    """
    plspassword = input("Insert Password for pls decryption :")
    key = hashlib.sha256(plspassword.encode()).digest()
    plsh.decrypt_file(key, 'pls.txt.enc', 'out.txt')

    # load PLS as ints
    pls = np.genfromtxt('out.txt', delimiter='\t', dtype=int)

    # cleanup helper files
    if os.path.exists("out.txt"):
        os.remove("out.txt")
    if os.path.exists("pls.txt.enc"):
        os.remove("pls.txt.enc")

    # normalize pls into an integer 1-D array
    pls = np.atleast_1d(pls).flatten().astype(int)

    # Calculate how many bytes were encoded (PLS length is n_bytes * 3)
    if len(pls) == 0:
        return ""  # nothing encoded

    n_bytes = len(pls) // 3

    decoded_bytes = bytearray()

    stegoImage = Image.open(r"images/out1.png")

    # Reconstruct each byte using exactly the same order the encoder used
    for idx in range(n_bytes):
        ithChar_bits = ""
        base_index = idx * 3
        for j in range(3):
            pos = int(pls[base_index + j])
            rr = pos // col
            rc = pos % col
            rgb = stegoImage.getpixel((rr, rc))
            for k in rgb:
                if len(ithChar_bits) >= 8:
                    break
                ithChar_bits += '1' if (k & 1) else '0'

        # ensure we have exactly 8 bits before converting
        if len(ithChar_bits) == 8:
            decoded_bytes.append(int(ithChar_bits, 2))
        else:
            # partial byte — skip (shouldn't happen if encode and PLS are consistent)
            pass

    # return as latin-1 string (1:1 mapping to bytes) to keep compatibility with existing AES flow
    return decoded_bytes.decode('latin-1')