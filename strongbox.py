#!/usr/bin/env python3


import argparse
import os
import hashlib
from ecies.utils import generate_eth_key, generate_key
from ecies import encrypt, decrypt

def generate_key_pair():
    # 生成secp256k1密钥对
    eth_key = generate_eth_key()
    return eth_key

def encrypt_file(input_file, public_key, output_file):
    with open(input_file, "rb") as f:
        plaintext = f.read()

    # 使用公钥加密文件内容
    ciphertext = encrypt(public_key, plaintext)

    # 计算SHA-256哈希值的前6位
    sha256_hash = hashlib.sha256(ciphertext).hexdigest()[:6]

    file_name = output_file.replace(".bin","_enc_" + sha256_hash + ".bin")

    # 写入加密数据到带有SHA-256哈希前6位的文件
    with open(file_name, "wb") as f:
        f.write(ciphertext)

def decrypt_file(input_file, private_key, output_file):
    with open(input_file, "rb") as f:
        ciphertext = f.read()

    # 使用私钥解密文件内容
    plaintext = decrypt(private_key, ciphertext)

    # 写入解密数据到输出文件
    with open(output_file, "wb") as f:
        f.write(plaintext)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encrypt, decrypt, or generate key pair using secp256k1.")
    parser.add_argument("--enc", help="Encrypt a file")
    parser.add_argument("--dec", help="Decrypt a file")
    parser.add_argument("--gen", help="Generate a key pair")
    parser.add_argument("--key", help="Path to the key file (public or private)")
    args = parser.parse_args()

    if args.gen and args.gen.endswith(".key"):
        key_pair = generate_key_pair()
        public_key = key_pair.public_key.to_hex()
        private_key = key_pair.to_hex()
        with open(args.gen, "w") as key_file:
            key_file.write(f"Public Key: {public_key}\nPrivate Key: {private_key}")
            print(f"Key pair generated and saved in '{args.gen}'")

    elif args.enc and args.key.endswith(".key") :
        with open(args.key, "r") as key_file:
            lines = key_file.readlines()
            public_key = lines[0].split(":")[1].strip()
            private_key = lines[1].split(":")[1].strip()
            output_file = args.enc + ".bin"
            encrypt_file(args.enc, public_key, output_file)
            print(f"File '{args.enc}' encrypted and saved as '{output_file}'")
            os.remove(args.enc)

    elif args.dec and args.key.endswith(".key") :
        with open(args.key, "r") as key_file:
            lines = key_file.readlines()
            private_key = lines[1].split(":")[1].strip()
            output_file = args.dec[:-15]
            decrypt_file(args.dec, private_key, output_file)
            print(f"File '{args.dec}' decrypted and saved as '{output_file}'")
    else :
        print("Usage: ")
        print("    ./strongbox --gen xxx.key                   # To generate a key pair[secp256k1].")
        print("    ./strongbox --key xxx.key --enc file        # To encrypt a file.")
        print("    ./strongbox --key xxx.key --dec file.bin    # To decrypt a encrypted file.")
