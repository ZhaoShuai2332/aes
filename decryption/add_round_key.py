"""
AES AddRoundKey - Decryption Module
Stage 2: AddRoundKey (same as encryption, since XOR is self-inverse)
"""


def add_round_key(state, round_key):
    """
    AddRoundKey: XOR state matrix with round key
    
    Same as encryption since a XOR b XOR b = a
    
    Args:
        state: 4x4 state matrix (list of lists)
        round_key: 4x4 round key matrix (list of lists)
    
    Returns:
        XORed 4x4 state matrix
    """
    result = []
    for i in range(4):
        row = []
        for j in range(4):
            row.append(state[i][j] ^ round_key[i][j])
        result.append(row)
    return result


if __name__ == "__main__":
    # Test AddRoundKey
    test_state = [
        [0x32, 0x88, 0x31, 0xe0],
        [0x43, 0x5a, 0x31, 0x37],
        [0xf6, 0x30, 0x98, 0x07],
        [0xa8, 0x8d, 0xa2, 0x34]
    ]
    
    test_round_key = [
        [0x2b, 0x28, 0xab, 0x09],
        [0x7e, 0xae, 0xf7, 0xcf],
        [0x15, 0xd2, 0x15, 0x4f],
        [0x16, 0xa6, 0x88, 0x3c]
    ]
    
    result = add_round_key(test_state, test_round_key)
    
    print("AddRoundKey Test (Decryption Module):")
    print("State matrix:")
    for row in test_state:
        print([hex(b) for b in row])
    
    print("\nRound key:")
    for row in test_round_key:
        print([hex(b) for b in row])
    
    print("\nXOR result:")
    for row in result:
        print([hex(b) for b in row])
