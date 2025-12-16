"""
AES Key Expansion - Decryption Module
Stage 1: Key Expansion (same as encryption)

Reuses key expansion implementation from encryption module
"""

# Import key expansion function from encryption module
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from encryption.key_expansion import key_expansion, S_BOX, RCON, rot_word, sub_word, xor_words

# Re-export for standalone use of decryption module
__all__ = ['key_expansion', 'S_BOX', 'RCON', 'rot_word', 'sub_word', 'xor_words']


if __name__ == "__main__":
    # Test key expansion (same as encryption module)
    test_key = bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                      0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])
    
    round_keys = key_expansion(test_key)
    
    print("AES-128 Key Expansion Result (Decryption Module Test):")
    print(f"Number of round keys generated: {len(round_keys)}")
    for i, rk in enumerate(round_keys):
        print(f"\nRound Key {i}:")
        for row in rk:
            print([hex(b) for b in row])
