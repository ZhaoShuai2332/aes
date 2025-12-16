"""
AES ShiftRows
Stage 4: Circular left shift of each row in the state matrix

ShiftRows provides the diffusion property of AES
- Row 0: No shift
- Row 1: Circular left shift by 1
- Row 2: Circular left shift by 2
- Row 3: Circular left shift by 3
"""


def shift_rows(state):
    """
    ShiftRows: Circular left shift of each row in the state matrix
    
    Shift rules:
    Row 0: [s0,0  s0,1  s0,2  s0,3] -> [s0,0  s0,1  s0,2  s0,3]  (unchanged)
    Row 1: [s1,0  s1,1  s1,2  s1,3] -> [s1,1  s1,2  s1,3  s1,0]  (left shift 1)
    Row 2: [s2,0  s2,1  s2,2  s2,3] -> [s2,2  s2,3  s2,0  s2,1]  (left shift 2)
    Row 3: [s3,0  s3,1  s3,2  s3,3] -> [s3,3  s3,0  s3,1  s3,2]  (left shift 3)
    
    Args:
        state: 4x4 state matrix (list of lists)
    
    Returns:
        Shifted 4x4 state matrix
    """
    result = [
        state[0][:],                                    # Row 0: no shift
        state[1][1:] + state[1][:1],                    # Row 1: left shift 1
        state[2][2:] + state[2][:2],                    # Row 2: left shift 2
        state[3][3:] + state[3][:3]                     # Row 3: left shift 3
    ]
    return result


if __name__ == "__main__":
    # Test ShiftRows
    test_state = [
        [0xd4, 0xe0, 0xb8, 0x1e],
        [0x27, 0xbf, 0xb4, 0x41],
        [0x11, 0x98, 0x5d, 0x52],
        [0xae, 0xf1, 0xe5, 0x30]
    ]
    
    result = shift_rows(test_state)
    
    print("ShiftRows Test:")
    print("Input state matrix:")
    for i, row in enumerate(test_state):
        print(f"Row {i}: {[hex(b) for b in row]}")
    
    print("\nOutput state matrix:")
    for i, row in enumerate(result):
        print(f"Row {i}: {[hex(b) for b in row]}")
    
    # Verify shifts
    print("\nVerification:")
    print(f"Row 0 unchanged: {test_state[0] == result[0]}")
    print(f"Row 1 left shift 1: {test_state[1][1:] + test_state[1][:1] == result[1]}")
    print(f"Row 2 left shift 2: {test_state[2][2:] + test_state[2][:2] == result[2]}")
    print(f"Row 3 left shift 3: {test_state[3][3:] + test_state[3][:3] == result[3]}")
