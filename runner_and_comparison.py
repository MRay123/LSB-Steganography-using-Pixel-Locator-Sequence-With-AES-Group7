import os
import shutil

import LSB as lsb
import AES as Cipher
from algorithms import blowfish_algorithm as CipherTwo
from algorithms import triple_DES as CipherThree

def run_all_algorithms_and_compare(secretMessage, passwordText):
   
    algorithms = [
        ("AES", Cipher.encrypt),
        ("BLOWFISH", CipherTwo.encrypt),
        ("3DES", CipherThree.encrypt),
    ]

    results = []

    #File cleanup
    for path in ["out.txt", "pls.txt.enc", "pls.txt", "images/out1.png"]:
        if os.path.exists(path):
            os.remove(path)

    if not os.path.exists("images/in1.png"):
        raise FileNotFoundError("Cover image images/in1.png is missing.")

    for algo_name, enc_func in algorithms:
        print(f"\n[*] Encrypting and hiding with {algo_name}...")

        #LSB Global cleanup
        lsb.PLS.clear()
        lsb.img = lsb.Image.open(r"images/in1.png")
        lsb.row, lsb.col = lsb.img.size

        # Encrypt
        encodedMessage = enc_func(secretMessage, passwordText)

        #displays the encrypted message just to show they're different
        print(f"\n{algo_name} ciphertext (hex):")
        print(encodedMessage)

        #LSB Encoding
        lsb.LsbEncoding(encodedMessage)

        #File naming convention stuff
        out_path = f"images/out_{algo_name}.png"
        os.makedirs("images", exist_ok=True)
        shutil.copy("images/out1.png", out_path)

        results.append((algo_name, out_path, os.path.getsize(out_path)))

        #PLS
        if os.path.exists("pls.txt"):
            os.remove("pls.txt")

    return results


def print_comparison_table(results):
    print("\n=== Stego Image Comparison ===")
    print(f"{'Algorithm':10} {'Output Image':25} {'Size (bytes)':12}")
    print("-" * 50)

    for algo, path, size in results:
        print(f"{algo:10} {path:25} {size:12d}")

    print("\nGenerated images:")
    for algo, path, _ in results:
        print(f"  {algo:10} -> {path}")
