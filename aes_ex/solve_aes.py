"""
AES Encryption Solution
Problem:
- Plaintext: 000102030405060708090A0B0C0D0E0F
- Key: 01010101010101010101010101010101 (hexadecimal)
- Use AES to encrypt

Every step has detailed print output
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from encryption.key_expansion import key_expansion
from encryption.add_round_key import add_round_key
from encryption.sub_bytes import sub_bytes
from encryption.shift_rows import shift_rows
from encryption.mix_columns import mix_columns


def print_divider(title=""):
    """Print divider line"""
    print("=" * 70)
    if title:
        print(f"  {title}")
        print("=" * 70)


def print_state(state, title="State Matrix"):
    """Print state matrix"""
    print(f"\n{title}:")
    print("  +----------------------------------------+")
    for row in state:
        row_str = " ".join(f"{b:02x}" for b in row)
        print(f"  |  {row_str}  |")
    print("  +----------------------------------------+")
    
    # Also print linear representation
    linear = ""
    for col in range(4):
        for row in range(4):
            linear += f"{state[row][col]:02x}"
    print(f"  Linear: {linear}")


def print_round_key(round_key, round_num):
    """Print round key"""
    print(f"\nRound Key K{round_num}:")
    print("  +----------------------------------------+")
    for row in round_key:
        row_str = " ".join(f"{b:02x}" for b in row)
        print(f"  |  {row_str}  |")
    print("  +----------------------------------------+")


def bytes_to_state(data):
    """Convert 16 bytes to 4x4 state matrix (column-major)"""
    state = []
    for row in range(4):
        state.append([data[row + 4*col] for col in range(4)])
    return state


def state_to_bytes(state):
    """Convert 4x4 state matrix back to 16 bytes"""
    result = []
    for col in range(4):
        for row in range(4):
            result.append(state[row][col])
    return bytes(result)


def aes_encrypt_detailed(plaintext_hex, key_hex):
    """
    AES encryption with detailed output for each step
    
    Args:
        plaintext_hex: Hexadecimal plaintext string
        key_hex: Hexadecimal key string
    
    Returns:
        Ciphertext bytes
    """
    Nr = 10  # AES-128 number of rounds
    
    # ========================================
    # Input parsing
    # ========================================
    print_divider("Problem Information")
    print(f"\nPlaintext (hex): {plaintext_hex}")
    print(f"Key (hex): {key_hex}")
    
    # Convert hex strings to bytes
    plaintext = bytes.fromhex(plaintext_hex)
    key = bytes.fromhex(key_hex)
    
    print(f"\nPlaintext (bytes): {list(plaintext)}")
    print(f"Key (bytes): {list(key)}")
    
    # ========================================
    # Stage 1: Key Expansion
    # ========================================
    print_divider("Stage 1: Key Expansion")
    print("\nExpanding 128-bit key to 11 round keys (44 words total)")
    
    round_keys = key_expansion(key)
    
    print(f"\nNumber of round keys generated: {len(round_keys)}")
    for i, rk in enumerate(round_keys):
        print_round_key(rk, i)
    
    # ========================================
    # Convert plaintext to state matrix
    # ========================================
    print_divider("Initialize State Matrix")
    
    state = bytes_to_state(plaintext)
    print_state(state, "Initial State Matrix (Plaintext)")
    
    # ========================================
    # Stage 2: Initial AddRoundKey
    # ========================================
    print_divider("Stage 2: Initial AddRoundKey")
    print("\nOperation: State = State XOR K0")
    
    print_state(state, "Input State")
    print_round_key(round_keys[0], 0)
    
    state = add_round_key(state, round_keys[0])
    print_state(state, "After AddRoundKey")
    
    # ========================================
    # Main rounds (1 to Nr-1)
    # ========================================
    for round_num in range(1, Nr):
        print_divider(f"Round {round_num}")
        
        # Stage 3: SubBytes
        print("\n[Stage 3: SubBytes]")
        print("Operation: Apply S-box substitution to each byte")
        print_state(state, "Before SubBytes")
        
        state = sub_bytes(state)
        print_state(state, "After SubBytes")
        
        # Stage 4: ShiftRows
        print("\n[Stage 4: ShiftRows]")
        print("Operation: Row 0 unchanged, Row 1 left 1, Row 2 left 2, Row 3 left 3")
        print_state(state, "Before ShiftRows")
        
        state = shift_rows(state)
        print_state(state, "After ShiftRows")
        
        # Stage 5: MixColumns
        print("\n[Stage 5: MixColumns]")
        print("Operation: Multiply each column with fixed polynomial matrix (GF(2^8))")
        print_state(state, "Before MixColumns")
        
        state = mix_columns(state)
        print_state(state, "After MixColumns")
        
        # Stage 2: AddRoundKey
        print(f"\n[Stage 2: AddRoundKey]")
        print(f"Operation: State = State XOR K{round_num}")
        print_state(state, "Before AddRoundKey")
        print_round_key(round_keys[round_num], round_num)
        
        state = add_round_key(state, round_keys[round_num])
        print_state(state, "After AddRoundKey")
    
    # ========================================
    # Final round (Round 10) - No MixColumns
    # ========================================
    print_divider(f"Round {Nr} (Final Round) - No MixColumns")
    
    # Stage 3: SubBytes
    print("\n[Stage 3: SubBytes]")
    print_state(state, "Before SubBytes")
    
    state = sub_bytes(state)
    print_state(state, "After SubBytes")
    
    # Stage 4: ShiftRows
    print("\n[Stage 4: ShiftRows]")
    print_state(state, "Before ShiftRows")
    
    state = shift_rows(state)
    print_state(state, "After ShiftRows")
    
    # Note: Final round skips MixColumns
    print("\n[Note: Final round skips MixColumns]")
    
    # Stage 2: AddRoundKey
    print(f"\n[Stage 2: AddRoundKey]")
    print(f"Operation: State = State XOR K{Nr}")
    print_state(state, "Before AddRoundKey")
    print_round_key(round_keys[Nr], Nr)
    
    state = add_round_key(state, round_keys[Nr])
    print_state(state, "After AddRoundKey (Final State)")
    
    # ========================================
    # Output result
    # ========================================
    ciphertext = state_to_bytes(state)
    
    print_divider("Encryption Complete - Final Result")
    print(f"\nPlaintext (hex): {plaintext_hex}")
    print(f"Key (hex): {key_hex}")
    print(f"\nCiphertext (hex): {ciphertext.hex().upper()}")
    print(f"Ciphertext (bytes): {list(ciphertext)}")
    
    return ciphertext


def answer_questions(plaintext_hex, key_hex):
    """
    Answer all required questions from the problem
    """
    # Convert hex strings to bytes
    plaintext = bytes.fromhex(plaintext_hex)
    key = bytes.fromhex(key_hex)
    
    # Generate round keys
    round_keys = key_expansion(key)
    
    # Initial state
    initial_state = bytes_to_state(plaintext)
    
    # After initial AddRoundKey
    state_after_initial_ark = add_round_key(initial_state, round_keys[0])
    
    # Round 1 stages
    state_after_subbytes = sub_bytes(state_after_initial_ark)
    state_after_shiftrows = shift_rows(state_after_subbytes)
    state_after_mixcolumns = mix_columns(state_after_shiftrows)
    
    print_divider("Question Answers")
    
    # Question 1
    print("\n[Question 1] Describe the initial State using a 4x4 matrix")
    print("\nAnswer:")
    print("  +----------------------------------------+")
    for row in initial_state:
        row_str = " ".join(f"{b:02x}" for b in row)
        print(f"  |  {row_str}  |")
    print("  +----------------------------------------+")
    
    # Question 2
    print("\n[Question 2] Give the value after initial round key addition")
    print("\nAnswer:")
    print("  +----------------------------------------+")
    for row in state_after_initial_ark:
        row_str = " ".join(f"{b:02x}" for b in row)
        print(f"  |  {row_str}  |")
    print("  +----------------------------------------+")
    linear = ""
    for col in range(4):
        for row in range(4):
            linear += f"{state_after_initial_ark[row][col]:02x}"
    print(f"  Linear: {linear}")
    
    # Question 3
    print("\n[Question 3] Give the value after byte substitution (Round 1 SubBytes)")
    print("\nAnswer:")
    print("  +----------------------------------------+")
    for row in state_after_subbytes:
        row_str = " ".join(f"{b:02x}" for b in row)
        print(f"  |  {row_str}  |")
    print("  +----------------------------------------+")
    linear = ""
    for col in range(4):
        for row in range(4):
            linear += f"{state_after_subbytes[row][col]:02x}"
    print(f"  Linear: {linear}")
    
    # Question 4
    print("\n[Question 4] Give the value after row shift (Round 1 ShiftRows)")
    print("\nAnswer:")
    print("  +----------------------------------------+")
    for row in state_after_shiftrows:
        row_str = " ".join(f"{b:02x}" for b in row)
        print(f"  |  {row_str}  |")
    print("  +----------------------------------------+")
    linear = ""
    for col in range(4):
        for row in range(4):
            linear += f"{state_after_shiftrows[row][col]:02x}"
    print(f"  Linear: {linear}")
    
    # Question 5
    print("\n[Question 5] Give the value after column mixing (Round 1 MixColumns)")
    print("\nAnswer:")
    print("  +----------------------------------------+")
    for row in state_after_mixcolumns:
        row_str = " ".join(f"{b:02x}" for b in row)
        print(f"  |  {row_str}  |")
    print("  +----------------------------------------+")
    linear = ""
    for col in range(4):
        for row in range(4):
            linear += f"{state_after_mixcolumns[row][col]:02x}"
    print(f"  Linear: {linear}")
    
    # Question 6
    print("\n[Question 6] Give the round key used in round 1 (K1)")
    print("\nAnswer:")
    print("  +----------------------------------------+")
    for row in round_keys[1]:
        row_str = " ".join(f"{b:02x}" for b in row)
        print(f"  |  {row_str}  |")
    print("  +----------------------------------------+")
    linear = ""
    for col in range(4):
        for row in range(4):
            linear += f"{round_keys[1][row][col]:02x}"
    print(f"  Linear: {linear}")
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    # ========================================
    # Problem requirements
    # ========================================
    # Plaintext: 000102030405060708090A0B0C0D0E0F
    # Key: 01010101010101010101010101010101
    # Use AES to encrypt
    
    print("\n" + "*" * 35)
    print("  AES-128 Encryption Solution")
    print("*" * 35 + "\n")
    
    plaintext = "000102030405060708090A0B0C0D0E0F"
    key = "01010101010101010101010101010101"
    
    ciphertext = aes_encrypt_detailed(plaintext, key)
    
    print("\n" + "*" * 35)
    print(f"  Final Ciphertext: {ciphertext.hex().upper()}")
    print("*" * 35 + "\n")
    
    # Answer all questions
    answer_questions(plaintext, key)
    
    print("\n" + "*" * 35)
    print("  All Questions Answered")
    print("*" * 35 + "\n")
