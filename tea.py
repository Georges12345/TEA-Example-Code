import struct
import binascii
import base64

def encrypt(message, key):
    # Convert the key to a tuple of four 32-bit integers
    key = struct.unpack('4L', key.ljust(32, b'\0'))
    
    # Encryption loop
    delta = 0x9E3779B9
    sum_ = 0
    v0, v1 = struct.unpack('2L', b'\0' * 16)
    ciphertext = b''
    for i in range(0, len(message), 16):
        v0, v1 = struct.unpack('2Q', message[i:i+16])
        sum_ = (sum_ + delta) & 0xffffffff
        for j in range(32):
            v0 = (v0 + (((v1<<4 ^ v1>>5) + v1) ^ (sum_ + key[sum_>>11 & 3]))) & 0xffffffff
            sum_ = (sum_ + delta) & 0xffffffff
            v1 = (v1 + (((v0<<4 ^ v0>>5) + v0) ^ (sum_ + key[sum_ & 3]))) & 0xffffffff
        ciphertext += struct.pack('2L', v0, v1)
    
    return ciphertext

def decrypt(ciphertext, key):
    # Convert the key to a tuple of four 32-bit integers
    key = struct.unpack('4L', key.ljust(32, b'\0'))
    
    # Decryption loop
    delta = 0x9E3779B9
    sum_ = (delta * 32) & 0xffffffff
    v0, v1 = struct.unpack('2L', b'\0' * 16)
    plaintext = b''
    for i in range(0, len(ciphertext), 16):
        v0, v1 = struct.unpack('2Q', ciphertext[i:i+16])
        for j in range(32):
            v1 = (v1 - (((v0<<4 ^ v0>>5) + v0) ^ (sum_ + key[sum_ & 3]))) & 0xffffffff
            sum_ = (sum_ - delta) & 0xffffffff
            v0 = (v0 - (((v1<<4 ^ v1>>5) + v1) ^ (sum_ + key[sum_>>11 & 3]))) & 0xffffffff
        plaintext += struct.pack('2Q', v0, v1)
    
    return plaintext



message = b"Hello, this is a secret message."
key = b'\x12\x34\x56\x78\x9a\xbc\xde\xf0\x12\x34\x56\x78\x9a\xbc\xde\xf0'

ciphertext = encrypt(message, key)
print("Encrypted message:", binascii.hexlify(ciphertext).decode())

decrypted_message = decrypt(ciphertext, key)
decoded_message = base64.b64encode(decrypted_message).decode('utf-8')
print("Decrypted message:", decoded_message)
