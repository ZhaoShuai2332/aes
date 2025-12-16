"""
AES Differential Characteristics Analysis
Demonstrates differential characteristics of AES algorithm for the first three rounds

This script uses the project's AES encryption modules to track differential propagation
"""

import sys
sys.path.insert(0, 'd:/projects/aes')

from encryption.key_expansion import key_expansion
from encryption.add_round_key import add_round_key
from encryption.sub_bytes import sub_bytes
from encryption.shift_rows import shift_rows
from encryption.mix_columns import mix_columns


def bytes_to_state(data):
    """Convert 16 bytes of data to 4x4 state matrix"""
    state = []
    for row in range(4):
        state.append([data[row + 4*col] for col in range(4)])
    return state


def xor_state(state1, state2):
    """Calculate XOR (difference) of two state matrices"""
    result = []
    for i in range(4):
        row = []
        for j in range(4):
            row.append(state1[i][j] ^ state2[i][j])
        result.append(row)
    return result


def count_active_bytes(state):
    """Count active bytes (non-zero bytes) in state matrix"""
    count = 0
    for row in state:
        for byte in row:
            if byte != 0:
                count += 1
    return count


def print_state(state, title=""):
    """Print state matrix"""
    if title:
        print(title)
    for row in state:
        print("  " + " ".join(f"{b:02x}" for b in row))


def print_diff_state(state, title=""):
    """Print differential state matrix, mark active bytes with *"""
    if title:
        print(title)
    for row in state:
        line = "  "
        for b in row:
            if b != 0:
                line += f"*{b:02x} "  # Active byte marked with *
            else:
                line += " 00 "  # Zero byte (no difference)
        print(line)
    print(f"  Active bytes: {count_active_bytes(state)}")


def visualize_diff_pattern(state):
    """Visualize differential pattern, use * for active, . for inactive"""
    lines = []
    for row in state:
        line = "  "
        for b in row:
            if b != 0:
                line += "* "
            else:
                line += ". "
        lines.append(line)
    return lines


def differential_analysis(plaintext1, plaintext2, key, num_rounds=3):
    """
    AES Differential Analysis - Track differential propagation for first three rounds
    
    Args:
        plaintext1: First plaintext (16 bytes)
        plaintext2: Second plaintext (16 bytes)
        key: Key (16 bytes)
        num_rounds: Number of rounds to analyze
    """
    print("=" * 70)
    print("AES Differential Characteristics Analysis - First 3 Rounds")
    print("=" * 70)
    
    # Key expansion
    round_keys = key_expansion(key)
    
    # Convert to state matrix
    state1 = bytes_to_state(plaintext1)
    state2 = bytes_to_state(plaintext2)
    
    # Calculate initial difference
    diff = xor_state(state1, state2)
    
    print("\n[Initial State]")
    print("\nPlaintext P1:")
    print_state(state1)
    print("\nPlaintext P2:")
    print_state(state2)
    print("\nInput Difference dP = P1 XOR P2:")
    print_diff_state(diff)
    print("\nDifference Pattern:")
    for line in visualize_diff_pattern(diff):
        print(line)
    
    # Initial AddRoundKey
    print("\n" + "-" * 70)
    print("[AddRoundKey - Round 0]")
    print("-" * 70)
    
    state1 = add_round_key(state1, round_keys[0])
    state2 = add_round_key(state2, round_keys[0])
    diff = xor_state(state1, state2)
    
    print("\nDifference after AddRoundKey (same as input, since K XOR K = 0):")
    print_diff_state(diff)
    
    # First three rounds
    for round_num in range(1, num_rounds + 1):
        print("\n" + "=" * 70)
        print(f"[Round {round_num}]")
        print("=" * 70)
        
        # SubBytes
        print("\n--- SubBytes ---")
        state1_before = [row[:] for row in state1]
        state2_before = [row[:] for row in state2]
        
        state1 = sub_bytes(state1)
        state2 = sub_bytes(state2)
        diff = xor_state(state1, state2)
        
        print("Difference after SubBytes:")
        print_diff_state(diff)
        print("Difference Pattern:")
        for line in visualize_diff_pattern(diff):
            print(line)
        
        # ShiftRows
        print("\n--- ShiftRows ---")
        state1 = shift_rows(state1)
        state2 = shift_rows(state2)
        diff = xor_state(state1, state2)
        
        print("Difference after ShiftRows:")
        print_diff_state(diff)
        print("Difference Pattern:")
        for line in visualize_diff_pattern(diff):
            print(line)
        
        # MixColumns (not in last round)
        if round_num < 10:
            print("\n--- MixColumns ---")
            state1 = mix_columns(state1)
            state2 = mix_columns(state2)
            diff = xor_state(state1, state2)
            
            print("Difference after MixColumns:")
            print_diff_state(diff)
            print("Difference Pattern:")
            for line in visualize_diff_pattern(diff):
                print(line)
        
        # AddRoundKey
        print("\n--- AddRoundKey ---")
        state1 = add_round_key(state1, round_keys[round_num])
        state2 = add_round_key(state2, round_keys[round_num])
        diff = xor_state(state1, state2)
        
        print("Difference after AddRoundKey:")
        print_diff_state(diff)
        print("Difference Pattern:")
        for line in visualize_diff_pattern(diff):
            print(line)
        
        print(f"\nRound {round_num} complete, active bytes: {count_active_bytes(diff)}")
    
    print("\n" + "=" * 70)
    print("Analysis Complete")
    print("=" * 70)


if __name__ == "__main__":
    print("AES Differential Characteristics Analysis")
    print("Demonstrating differential characteristics for first 3 rounds\n")
    
    # Define key
    key = bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])
    
    # Plaintext 1
    plaintext1 = bytes([0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34])
    
    # Plaintext 2: differs from plaintext1 only in first byte (single-byte difference)
    # Difference: 0x32 ^ 0x33 = 0x01 (difference only in first byte)
    plaintext2 = bytes([0x33, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34])
    
    # Execute differential analysis
    differential_analysis(plaintext1, plaintext2, key, num_rounds=3)
