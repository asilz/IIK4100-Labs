from pyaes import AESModeOfOperationECB

# 32-hex-digit strings → 16 bytes
key       = bytes.fromhex("05deadbeef42006861636b65646b6579")
plaintext = bytes.fromhex("2923be84e16cd6ae529049f1f1bbe9eb")

aes = AESModeOfOperationECB(key)
ciphertext = aes.encrypt(plaintext)

print("Ciphertext (hex):", ciphertext.hex())
