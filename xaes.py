#!/usr/bin/env python3

import sys
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

KEY_SIZE = 16
IV_SIZE = 16
SALT_SIZE = 8
PBKDF2_ITERATIONS = 10000
OPENSSL_SALT_HEADER = b"Salted__"

def derive_key_iv(password: bytes, salt: bytes, key_len: int, iv_len: int) -> tuple[bytes, bytes]:
    derived = PBKDF2(password, salt, dkLen=(key_len + iv_len), count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)
    key = derived[:key_len]
    iv = derived[key_len:key_len + iv_len]
    return key, iv

def encrypt(data: bytes, password_str: str) -> bytes:
    password_bytes = password_str.encode('utf-8')
    salt = get_random_bytes(SALT_SIZE)
    
    key, iv = derive_key_iv(password_bytes, salt, KEY_SIZE, IV_SIZE)
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    padded_data = pad(data, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    
    return OPENSSL_SALT_HEADER + salt + ciphertext

def decrypt(data: bytes, password_str: str) -> bytes:
    password_bytes = password_str.encode('utf-8')
    
    if not data.startswith(OPENSSL_SALT_HEADER):
        raise ValueError("El archivo no parece estar en formato OpenSSL (falta cabecera 'Salted__')")
        
    salt_header_len = len(OPENSSL_SALT_HEADER)
    salt = data[salt_header_len : salt_header_len + SALT_SIZE]
    ciphertext_actual = data[salt_header_len + SALT_SIZE :]
    key, iv = derive_key_iv(password_bytes, salt, KEY_SIZE, IV_SIZE)
    
    cipher = AES.new(key, AES.MODE_CBC, iv)

    decrypted_padded_data = cipher.decrypt(ciphertext_actual)
    plaintext = unpad(decrypted_padded_data, AES.block_size)
    
    return plaintext

def main():
    if len(sys.argv) != 3:
        sys.stderr.write(f"Uso: {sys.argv[0]} -e|-d <contraseña>\n")
        sys.stderr.write("Ejemplo cifrar:   cat myfile | ./xaes.py -e \"mypass\" > myfile.enc\n")
        sys.stderr.write("Ejemplo descifrar: cat myfile.enc | ./xaes.py -d \"mypass\" > myfile.dec\n")
        sys.exit(1)

    mode_flag = sys.argv[1]
    password_str = sys.argv[2]
    
    input_data = sys.stdin.buffer.read()
    output_data = None

    try:
        if mode_flag == "-e":
            output_data = encrypt(input_data, password_str)
        elif mode_flag == "-d":
            output_data = decrypt(input_data, password_str)
        else:
            sys.stderr.write(f"Error: Opción desconocida '{mode_flag}'. Use -e para cifrar o -d para descifrar.\n")
            sys.exit(1)
        
        sys.stdout.buffer.write(output_data)

    except Exception as e:
        sys.stderr.write(f"Error inesperado: {e}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()

    