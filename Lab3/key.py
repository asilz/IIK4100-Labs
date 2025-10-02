#!/usr/bin/env python3
"""
Recover AES round-10 key and original AES-128 key from:
 - M9: the 16-byte state before the final (10th) AES round
 - C:  the 16-byte genuine ciphertext

Assumes AES-128 (10 rounds), standard S-box, standard key schedule.
"""

from struct import pack, unpack

# --- AES S-box and SubBytes ---
SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

def sbox_bytes(data: bytes) -> bytes:
    """Apply AES S-box to each byte."""
    return bytes(SBOX[b] for b in data)

# --- ShiftRows / inverse ShiftRows on 16-byte state ---
def shift_rows(state: bytes) -> bytes:
    """
    AES ShiftRows: row r (0..3) is left-rotated by r.
    State is column-major: byte index = r + 4*c.
    """
    s = list(state)
    out = [0]*16
    for idx in range(16):
        r = idx % 4
        c = idx // 4
        # after ShiftRows: pos (r,c) takes from (r, (c+r)%4)
        src_c = (c + r) % 4
        src_idx = r + 4*src_c
        out[idx] = s[src_idx]
    return bytes(out)

# --- Invert AES final round to get K10 ---
def recover_round10_key(M9: bytes, C: bytes) -> bytes:
    """
    Given:
      M9 : 16-byte state before final round
      C  : 16-byte ciphertext
    Returns:
      K10: 16-byte round-10 key
    """
    # 1) SubBytes → ShiftRows
    sub = sbox_bytes(M9)
    sr  = shift_rows(sub)
    # 2) AddRoundKey: C = SR ^ K10   ⇒  K10 = C ^ SR
    return bytes(c ^ s for c,s in zip(C, sr))


# --- Invert AES-128 key expansion for one round ---
def inv_expand_key_128(next_key: bytes, rcon: int) -> bytes:
    """
    Invert a single AES-128 key-expansion step.
    
    next_key: 16-byte round key for round i
    rcon:      corresponding round-constant for that step (0x01 for round1, … 0x36 for round10)
    
    Returns: 16-byte round key for round i-1.
    """
    # split into words
    nb = unpack(">4I", next_key)
    # recover prev k1,k2,k3:
    k1 = nb[0] ^ nb[1]
    k2 = nb[1] ^ nb[2]
    k3 = nb[2] ^ nb[3]
    # compute k4a = SubWord(RotWord(k3))
    rot_k3 = ((k3 << 8) & 0xFFFFFFFF) | (k3 >> 24)
    # SubWord: apply SBOX to each of 4 bytes
    k4a = 0
    for shift in (24,16,8,0):
        byte = (rot_k3 >> shift) & 0xFF
        k4a |= SBOX[byte] << shift
    # recover v0 = nb0 ^ k4a
    v0 = nb[0] ^ k4a
    # v0 bytes
    v0b = pack(">I", v0)
    # v0 = ((k0>>24)^rcon)<<24 | (k0&0x00FFFFFF)
    # so k0 bytes = [ v0b[0]^rcon, v0b[1], v0b[2], v0b[3] ]
    k0b = bytes([v0b[0] ^ rcon, v0b[1], v0b[2], v0b[3]])
    # now pack prev key words
    prev = k0b + pack(">I", k1) + pack(">I", k2) + pack(">I", k3)
    return prev

# --- Full inversion back to original key ---
def recover_master_key(K10: bytes) -> bytes:
    """
    Walk the key schedule backward from round-10 key to round-0 (master) key.
    """
    # rcon values for AES-128 rounds 1..10
    RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]
    round_keys = [None]*11
    round_keys[10] = K10
    # invert step by step
    for i in range(10, 0, -1):
        prev = inv_expand_key_128(round_keys[i], RCON[i-1])
        round_keys[i-1] = prev
    # round_keys[0] is the original cipher key
    return round_keys[0]

# --- Main utility ---
def hex2bytes(h: str) -> bytes:
    return bytes.fromhex(h.strip())

if __name__ == "__main__":
    # ——— Inputs ———
    # Replace these with your recovered M9 and genuine C:
    M9_hex = "00112233445566778899aabbccddeeff"  # <— put your 16-byte round-9 hex here
    C_hex  = "00112233445566778899aabbccddeeff"  # <— from your C: line in cipher_list.txt
    
    M9 = hex2bytes(M9_hex)
    C  = hex2bytes(C_hex)
    
    # 1) recover round-10 key
    K10 = recover_round10_key(M9, C)
    print("Recovered K10 =", K10.hex())
    
    # 2) recover master (round-0) key
    K0 = recover_master_key(K10)
    print("Recovered AES-128 master key =", K0.hex())
