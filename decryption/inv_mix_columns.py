"""
AES InvMixColumns
Stage 5: Inverse matrix multiplication transformation for each column

Performs matrix multiplication in GF(2^8) finite field
Uses inverse polynomial matrix:
[0e 0b 0d 09]
[09 0e 0b 0d]
[0d 09 0e 0b]
[0b 0d 09 0e]
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


def inv_mix_single_column(column):
    """
    Apply inverse MixColumn transformation to a single column
    
    Matrix multiplication:
    [s'0]   [0e 0b 0d 09] [s0]
    [s'1] = [09 0e 0b 0d] [s1]
    [s'2]   [0d 09 0e 0b] [s2]
    [s'3]   [0b 0d 09 0e] [s3]
    
    Args:
        column: List of 4 bytes
    
    Returns:
        Transformed list of 4 bytes
    """
    s0, s1, s2, s3 = column
    
    # Calculate new column values
    r0 = gf_mult(0x0e, s0) ^ gf_mult(0x0b, s1) ^ gf_mult(0x0d, s2) ^ gf_mult(0x09, s3)
    r1 = gf_mult(0x09, s0) ^ gf_mult(0x0e, s1) ^ gf_mult(0x0b, s2) ^ gf_mult(0x0d, s3)
    r2 = gf_mult(0x0d, s0) ^ gf_mult(0x09, s1) ^ gf_mult(0x0e, s2) ^ gf_mult(0x0b, s3)
    r3 = gf_mult(0x0b, s0) ^ gf_mult(0x0d, s1) ^ gf_mult(0x09, s2) ^ gf_mult(0x0e, s3)
    
    return [r0, r1, r2, r3]


def inv_mix_columns(state):
    """
    InvMixColumns: Apply inverse column mixing transformation to each column
    
    Inverse of MixColumns:
    InvMixColumns(MixColumns(state)) = state
    
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
        # Inverse mix the column
        new_column = inv_mix_single_column(column)
        # Put back into result matrix
        for row in range(4):
            result[row][col] = new_column[row]
    
    return result


if __name__ == "__main__":
    # Test InvMixColumns
    # Use MixColumns output as input
    test_state = [
        [0x04, 0xe0, 0x48, 0x28],
        [0x66, 0xcb, 0xf8, 0x06],
        [0x81, 0x19, 0xd3, 0x26],
        [0xe5, 0x9a, 0x7a, 0x4c]
    ]
    
    result = inv_mix_columns(test_state)
    
    print("InvMixColumns Test:")
    print("Input state matrix:")
    for row in test_state:
        print([hex(b) for b in row])
    
    print("\nOutput state matrix:")
    for row in result:
        print([hex(b) for b in row])
    
    # Test GF multiplication with inverse constants
    print("\nGF(2^8) multiplication test (inverse constants):")
    print(f"0x57 * 0x0e = {hex(gf_mult(0x57, 0x0e))}")
    print(f"0x57 * 0x0b = {hex(gf_mult(0x57, 0x0b))}")
    print(f"0x57 * 0x0d = {hex(gf_mult(0x57, 0x0d))}")
    print(f"0x57 * 0x09 = {hex(gf_mult(0x57, 0x09))}")
