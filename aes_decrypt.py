"""
AES Decryption Main Entry Point
Implements complete AES-128 decryption process

Algorithm 23.9 AES decryption:
1. KeyExpansion - Key expansion
2. AddRoundKey - Initial round key addition (using round key Nr)
3. For round = Nr-1 down to 1:
   - InvShiftRows
   - InvSubBytes
   - AddRoundKey
   - InvMixColumns
4. Final round (no InvMixColumns):
   - InvShiftRows
   - InvSubBytes
   - AddRoundKey (using round key 0)
"""

from decryption.key_expansion import key_expansion
from decryption.add_round_key import add_round_key
from decryption.inv_sub_bytes import inv_sub_bytes
from decryption.inv_shift_rows import inv_shift_rows
from decryption.inv_mix_columns import inv_mix_columns


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


def decrypt_block(ciphertext, key, verbose=False):
    """
    Decrypt a single 16-byte block with AES
    
    Args:
        ciphertext: 16-byte ciphertext (bytes or list)
        key: 16-byte key (bytes or list)
        verbose: Whether to print intermediate states
    
    Returns:
        16-byte plaintext (bytes)
    """
    Nr = 10  # AES-128 number of rounds
    
    # Stage 1: Key expansion
    round_keys = key_expansion(key)
    if verbose:
        print("=== AES Decryption Start ===")
        print(f"\n[Stage 1] Key Expansion: Generated {len(round_keys)} round keys")
    
    # Convert ciphertext to state matrix
    state = bytes_to_state(ciphertext)
    if verbose:
        print("\nInitial state matrix (ciphertext):")
        print_state(state)
    
    # Stage 2: Initial AddRoundKey (using round key Nr)
    state = add_round_key(state, round_keys[Nr])
    if verbose:
        print("\n[Stage 2] After initial AddRoundKey:")
        print_state(state)
    
    # Main rounds (Nr-1 down to 1)
    for round_num in range(Nr - 1, 0, -1):
        if verbose:
            print(f"\n=== Round {Nr - round_num} (inverse of round {round_num}) ===")
        
        # Stage 4: InvShiftRows
        state = inv_shift_rows(state)
        if verbose:
            print(f"[Stage 4] After InvShiftRows:")
            print_state(state)
        
        # Stage 3: InvSubBytes
        state = inv_sub_bytes(state)
        if verbose:
            print(f"[Stage 3] After InvSubBytes:")
            print_state(state)
        
        # Stage 2: AddRoundKey
        state = add_round_key(state, round_keys[round_num])
        if verbose:
            print(f"[Stage 2] After AddRoundKey:")
            print_state(state)
        
        # Stage 5: InvMixColumns
        state = inv_mix_columns(state)
        if verbose:
            print(f"[Stage 5] After InvMixColumns:")
            print_state(state)
    
    # Final round (no InvMixColumns)
    if verbose:
        print(f"\n=== Round {Nr} (Final Round) ===")
    
    state = inv_shift_rows(state)
    if verbose:
        print("[Stage 4] After InvShiftRows:")
        print_state(state)
    
    state = inv_sub_bytes(state)
    if verbose:
        print("[Stage 3] After InvSubBytes:")
        print_state(state)
    
    state = add_round_key(state, round_keys[0])
    if verbose:
        print("[Stage 2] After AddRoundKey:")
        print_state(state)
    
    # Convert state matrix back to bytes
    plaintext = state_to_bytes(state)
    
    if verbose:
        print("\n=== AES Decryption Complete ===")
        print(f"Plaintext: {plaintext.hex()}")
    
    return plaintext


def print_state(state):
    """Print state matrix"""
    for row in state:
        print("  " + " ".join(f"{b:02x}" for b in row))


def decrypt(ciphertext, key):
    """
    AES decryption (supports arbitrary length ciphertext, removes PKCS7 padding)
    
    Args:
        ciphertext: Ciphertext (bytes)
        key: 16-byte key (bytes)
    
    Returns:
        Plaintext (bytes)
    """
    # Block-by-block decryption
    block_size = 16
    plaintext = b''
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i+block_size]
        plaintext += decrypt_block(block, key)
    
    # Remove PKCS7 padding
    padding_len = plaintext[-1]
    if padding_len > 0 and padding_len <= block_size:
        # Verify padding
        if all(b == padding_len for b in plaintext[-padding_len:]):
            plaintext = plaintext[:-padding_len]
    
    return plaintext


if __name__ == "__main__":
    # Using FIPS 197 standard test vectors
    print("=" * 60)
    print("AES-128 Decryption Test")
    print("=" * 60)
    
    # Test vector (from FIPS 197 Appendix B)
    test_key = bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                      0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])
    
    test_ciphertext = bytes([0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
                              0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32])
    
    expected_plaintext = bytes([0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                                 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34])
    
    print(f"\nKey: {test_key.hex()}")
    print(f"Ciphertext: {test_ciphertext.hex()}")
    
    # Perform decryption
    plaintext = decrypt_block(test_ciphertext, test_key, verbose=True)
    
    print(f"\nExpected plaintext: {expected_plaintext.hex()}")
    print(f"Actual plaintext: {plaintext.hex()}")
    print(f"Verification: {'PASS' if plaintext == expected_plaintext else 'FAIL'}")
    
    # Test encryption-decryption round trip
    print("\n" + "=" * 60)
    print("Encryption-Decryption Round Trip Test")
    print("=" * 60)
    
    from aes_encrypt import encrypt
    
    message = b"Hello, AES-128!"
    key = b"ThisIsASecretKey"
    
    print(f"Original message: {message.decode()}")
    print(f"Key: {key.decode()}")
    
    encrypted = encrypt(message, key)
    print(f"Encrypted result: {encrypted.hex()}")
    
    decrypted = decrypt(encrypted, key)
    print(f"Decrypted result: {decrypted.decode()}")
    print(f"Verification: {'PASS' if decrypted == message else 'FAIL'}")
