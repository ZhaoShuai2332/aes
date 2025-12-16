"""
AES MixColumns
Stage 5: Matrix multiplication transformation for each column of the state matrix

Performs matrix multiplication in GF(2^8) finite field
Uses fixed polynomial matrix:
[02 03 01 01]
[01 02 03 01]
[01 01 02 03]
[03 01 01 02]
"""


def xtime(a):
    """
    Multiply by 2 in GF(2^8) (i.e., multiply by x)
    
    If the high bit is 1, XOR with irreducible polynomial 0x1b after left shift
    
    Args:
        a: Single byte
    
    Returns:
        a * 2 in GF(2^8)
    """
    if a & 0x80:
        return ((a << 1) ^ 0x1b) & 0xff
    else:
        return (a << 1) & 0xff


def gf_mult(a, b):
    """
    GF(2^8) finite field multiplication
    
    Uses Russian peasant multiplication algorithm
    
    Args:
        a: First byte
        b: Second byte
    
    Returns:
        a * b in GF(2^8)
    """
    result = 0
    temp_a = a
    temp_b = b
    
    while temp_b:
        if temp_b & 1:
            result ^= temp_a
        temp_a = xtime(temp_a)
        temp_b >>= 1
    
    return result


def mix_single_column(column):
    """
    Apply MixColumn transformation to a single column
    
    Matrix multiplication:
    [s'0]   [02 03 01 01] [s0]
    [s'1] = [01 02 03 01] [s1]
    [s'2]   [01 01 02 03] [s2]
    [s'3]   [03 01 01 02] [s3]
    
    Args:
        column: List of 4 bytes
    
    Returns:
        Transformed list of 4 bytes
    """
    s0, s1, s2, s3 = column
    
    # Calculate new column values
    r0 = gf_mult(0x02, s0) ^ gf_mult(0x03, s1) ^ s2 ^ s3
    r1 = s0 ^ gf_mult(0x02, s1) ^ gf_mult(0x03, s2) ^ s3
    r2 = s0 ^ s1 ^ gf_mult(0x02, s2) ^ gf_mult(0x03, s3)
    r3 = gf_mult(0x03, s0) ^ s1 ^ s2 ^ gf_mult(0x02, s3)
    
    return [r0, r1, r2, r3]


def mix_columns(state):
    """
    MixColumns: Apply column mixing transformation to each column of the state matrix
    
    Args:
        state: 4x4 state matrix (row-major storage)
    
    Returns:
        Transformed 4x4 state matrix
    """
    # Extract each column, transform, and reassemble into state matrix
    result = [[0] * 4 for _ in range(4)]
    
    for col in range(4):
        # Extract column col
        column = [state[row][col] for row in range(4)]
        # Mix the column
        new_column = mix_single_column(column)
        # Put back into result matrix
        for row in range(4):
            result[row][col] = new_column[row]
    
    return result


if __name__ == "__main__":
    # Test MixColumns
    test_state = [
        [0xd4, 0xe0, 0xb8, 0x1e],
        [0xbf, 0xb4, 0x41, 0x27],
        [0x5d, 0x52, 0x11, 0x98],
        [0x30, 0xae, 0xf1, 0xe5]
    ]
    
    result = mix_columns(test_state)
    
    print("MixColumns Test:")
    print("Input state matrix:")
    for row in test_state:
        print([hex(b) for b in row])
    
    print("\nOutput state matrix:")
    for row in result:
        print([hex(b) for b in row])
    
    # Test GF multiplication
    print("\nGF(2^8) multiplication test:")
    print(f"0x57 * 0x02 = {hex(gf_mult(0x57, 0x02))}  (should be 0xae)")
    print(f"0x57 * 0x03 = {hex(gf_mult(0x57, 0x03))}  (should be 0xf9)")
    print(f"0x57 * 0x13 = {hex(gf_mult(0x57, 0x13))}  (should be 0xfe)")
