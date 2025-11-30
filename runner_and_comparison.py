import os
import shutil

import LSB as lsb
import AES as Cipher
from algorithms import blowfish_algorithm as CipherTwo
from algorithms import triple_DES as CipherThree
from time import perf_counter

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
        
        start_time = perf_counter()

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
        out_image_path = f"images/out_{algo_name}.png"
        os.makedirs("images", exist_ok=True)
        shutil.copy("images/out1.png", out_image_path)

        pls_enc_src = "pls.txt.enc"
        if os.path.exists(pls_enc_src):
             pls_enc_dst = f"pls_{algo_name}.txt.enc"
             shutil.copy(pls_enc_src, pls_enc_dst)
        else:
            print(f"[!] Warning: {pls_enc_src} not found after {algo_name} encoding")
           


        #PLS
        if os.path.exists("pls.txt"):
            os.remove("pls.txt")
            
        end_time = perf_counter()
        elapsed = end_time - start_time
        results.append((algo_name, out_image_path, os.path.getsize(out_image_path), elapsed))

    return results



def print_comparison_table(results):
    print("\n=== Stego Image Comparison ===")
    print(f"{'Algorithm':10} {'Output Image':25} {'Size (bytes)':12} {'Time (s)':10}")
    print("-" * 70)

    for algo, path, size, elapsed in results:
        print(f"{algo:10} {path:25} {size:12d} {elapsed:10.6f}")





def _get_decrypt_func_for_algo(algo_name: str):
    algo_name = algo_name.upper()
    if algo_name == "AES":
        return Cipher.decrypt
    elif algo_name == "BLOWFISH":
        return CipherTwo.decrypt
    elif algo_name == "3DES":
        return CipherThree.decrypt
    else:
        raise ValueError(f"Unknown algorithm: {algo_name}")


def decrypt_all_algorithms(passwordText: str):

    algorithms = ["AES", "BLOWFISh", "3DES"]

    for algo_name in algorithms:
        print(f"\n[*] Decrypting stego image for {algo_name}...")

        stego_image = f"images/out_{algo_name}.png"
        pls_enc_file = f"pls_{algo_name}.txt.enc"

        if not os.path.exists(stego_image):
            print(f"[!] Stego image not found: {stego_image} (skipping)")
            continue

        if not os.path.exists(pls_enc_file):
            print(f"[!] PLS file not found: {pls_enc_file} (skipping)")
            continue

        
        for path in ["images/out1.png", "pls.txt.enc", "pls.txt"]:
            if os.path.exists(path):
                os.remove(path)

        
        shutil.copy(stego_image, "images/out1.png")
        shutil.copy(pls_enc_file, "pls.txt.enc")

        decoded_cipher = lsb.LsbDecoding(
            pls_filename=pls_enc_file,
            stego_image=stego_image
        )

        # Convert raw bytes → hex
        decoded_bytes = decoded_cipher.encode("latin-1")
        decoded_cipher_hex = decoded_bytes.hex()

        
        print("\nExtracted ciphertext (hex):")
        print(decoded_cipher)

        decrypt_func = _get_decrypt_func_for_algo(algo_name)

        try:
            final_message = decrypt_func(decoded_cipher, passwordText)
            print(f"Final message for {algo_name}:", final_message)
        except Exception as e:
            print(f"[!] Decryption failed for {algo_name}: {e}")