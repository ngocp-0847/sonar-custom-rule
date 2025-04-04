from Crypto.Cipher import AES

# ❌ KHÔNG AN TOÀN: key và plaintext hardcoded
key = b'Sixteen byte key'  # 16 bytes cho AES-128
plaintext = b'Attack at dawn!'  # cần 16 bytes

# ❌ ECB mode KHÔNG AN TOÀN
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(plaintext)
print("Ciphertext:", ciphertext.hex())
