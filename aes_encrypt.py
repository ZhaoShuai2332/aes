"""
AES Encryption Main Entry Point
Implements complete AES-128 encryption process

Algorithm 23.6 AES encryption:
1. KeyExpansion - Key expansion
2. AddRoundKey - Initial round key addition
3. For round = 1 to Nr-1:
   - SubBytes
   - ShiftRows
   - MixColumns
   - AddRoundKey
4. Final round (no MixColumns):
   - SubBytes
   - ShiftRows
   - AddRoundKey
"""

from encryption.key_expansion import key_expansion
from encryption.add_round_key import add_round_key
from encryption.sub_bytes import sub_bytes
from encryption.shift_rows import shift_rows
from encryption.mix_columns import mix_columns


def bytes_to_state(data):
    """
    Convert 16 bytes of data to 4x4 state matrix
    
    AES uses column-major order:
    [b0  b4  b8  b12]
    [b1  b5  b9  b13]
    [b2  b6  b10 b14]
    [b3  b7  b11 b15]
    
    Args:
        data: 16-byte data (bytes or list)
    
    Returns:
        4x4 state matrix
    """
    state = []
    for row in range(4):
        state.append([data[row + 4*col] for col in range(4)])
    return state


def state_to_bytes(state):
    """
    Convert 4x4 state matrix back to 16 bytes of data
    
    Args:
        state: 4x4 state matrix
    
    Returns:
        16-byte data (bytes)
    """
    result = []
    for col in range(4):
        for row in range(4):
            result.append(state[row][col])
    return bytes(result)


def encrypt_block(plaintext, key, verbose=False):
    """
    Encrypt a single 16-byte block with AES
    
    Args:
        plaintext: 16-byte plaintext (bytes or list)
        key: 16-byte key (bytes or list)
        verbose: Whether to print intermediate states
    
    Returns:
        16-byte ciphertext (bytes)
    """
    Nr = 10  # AES-128 number of rounds
    
    # Stage 1: Key expansion
    round_keys = key_expansion(key)
    if verbose:
        print("=== AES Encryption Start ===")
        print(f"\n[Stage 1] Key Expansion: Generated {len(round_keys)} round keys")
    
    # Convert plaintext to state matrix
    state = bytes_to_state(plaintext)
    if verbose:
        print("\nInitial state matrix:")
        print_state(state)
    
    # Stage 2: Initial AddRoundKey
    state = add_round_key(state, round_keys[0])
    if verbose:
        print("\n[Stage 2] After initial AddRoundKey:")
        print_state(state)
    
    # Main rounds (1 to Nr-1)
    for round_num in range(1, Nr):
        if verbose:
            print(f"\n=== Round {round_num} ===")
        
        # Stage 3: SubBytes
        state = sub_bytes(state)
        if verbose:
            print(f"[Stage 3] After SubBytes:")
            print_state(state)
        
        # Stage 4: ShiftRows
        state = shift_rows(state)
        if verbose:
            print(f"[Stage 4] After ShiftRows:")
            print_state(state)
        
        # Stage 5: MixColumns
        state = mix_columns(state)
        if verbose:
            print(f"[Stage 5] After MixColumns:")
            print_state(state)
        
        # Stage 2: AddRoundKey
        state = add_round_key(state, round_keys[round_num])
        if verbose:
            print(f"[Stage 2] After AddRoundKey:")
            print_state(state)
    
    # Final round (no MixColumns)
    if verbose:
        print(f"\n=== Round {Nr} (Final Round) ===")
    
    state = sub_bytes(state)
    if verbose:
        print("[Stage 3] After SubBytes:")
        print_state(state)
    
    state = shift_rows(state)
    if verbose:
        print("[Stage 4] After ShiftRows:")
        print_state(state)
    
    state = add_round_key(state, round_keys[Nr])
    if verbose:
        print("[Stage 2] After AddRoundKey:")
        print_state(state)
    
    # Convert state matrix back to bytes
    ciphertext = state_to_bytes(state)
    
    if verbose:
        print("\n=== AES Encryption Complete ===")
        print(f"Ciphertext: {ciphertext.hex()}")
    
    return ciphertext


def print_state(state):
    """Print state matrix"""
    for row in state:
        print("  " + " ".join(f"{b:02x}" for b in row))


def encrypt(plaintext, key):
    """
    AES encryption (supports arbitrary length plaintext with PKCS7 padding)
    
    Args:
        plaintext: Plaintext (bytes)
        key: 16-byte key (bytes)
    
    Returns:
        Ciphertext (bytes)
    """
    # PKCS7 padding
    block_size = 16
    padding_len = block_size - (len(plaintext) % block_size)
    padded = plaintext + bytes([padding_len] * padding_len)
    
    # Block-by-block encryption
    ciphertext = b''
    for i in range(0, len(padded), block_size):
        block = padded[i:i+block_size]
        ciphertext += encrypt_block(block, key)
    
    return ciphertext


if __name__ == "__main__":
    # Using FIPS 197 standard test vectors
    print("=" * 60)
    print("AES-128 Encryption Test")
    print("=" * 60)
    
    # Test vector (from FIPS 197 Appendix B)
    test_key = bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                      0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])
    
    test_plaintext = bytes([0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                            0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34])
    
    expected_ciphertext = bytes([0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
                                  0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32])
    
    print(f"\nKey: {test_key.hex()}")
    print(f"Plaintext: {test_plaintext.hex()}")
    
    # Perform encryption
    ciphertext = encrypt_block(test_plaintext, test_key, verbose=True)
    
    print(f"\nExpected ciphertext: {expected_ciphertext.hex()}")
    print(f"Actual ciphertext: {ciphertext.hex()}")
    print(f"Verification: {'PASS' if ciphertext == expected_ciphertext else 'FAIL'}")
    
    # Test string encryption
    print("\n" + "=" * 60)
    print("String Encryption Test")
    print("=" * 60)
    
    message = b"Hello, AES-128!"
    key = b"ThisIsASecretKey"
    
    print(f"Original message: {message.decode()}")
    print(f"Key: {key.decode()}")
    
    encrypted = encrypt(message, key)
    print(f"Encrypted result: {encrypted.hex()}")
