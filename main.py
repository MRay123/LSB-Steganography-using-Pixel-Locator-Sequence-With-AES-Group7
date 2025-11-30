import LSB as lsb
import AES as Cipher
import os

from runner_and_comparison import (
    run_all_algorithms_and_compare,
    print_comparison_table,
    decrypt_all_algorithms,
)


def main():
    
    select = input("Enter E for Encoding D for Decoding :")
    
    if select == 'E' or select == 'e':
        message = input("Enter the secret message: ")
        password = input("Password: ")

        results = run_all_algorithms_and_compare(message, password)
        print_comparison_table(results)


    if select == 'D' or select == 'd':
        password = input("Enter the password for decryption: ")
        decrypt_all_algorithms(password)

    else:
        print("Invalid Selection")








main()
