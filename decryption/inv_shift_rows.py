"""
AES InvShiftRows
Stage 4: Circular right shift of each row (inverse of ShiftRows)

Inverse shift operation:
- Row 0: No shift
- Row 1: Circular right shift by 1
- Row 2: Circular right shift by 2
- Row 3: Circular right shift by 3
"""


def inv_shift_rows(state):
    """
    InvShiftRows: Circular right shift of each row in the state matrix
    
    Shift rules (opposite of ShiftRows):
    Row 0: [s0,0  s0,1  s0,2  s0,3] -> [s0,0  s0,1  s0,2  s0,3]  (unchanged)
    Row 1: [s1,0  s1,1  s1,2  s1,3] -> [s1,3  s1,0  s1,1  s1,2]  (right shift 1)
    Row 2: [s2,0  s2,1  s2,2  s2,3] -> [s2,2  s2,3  s2,0  s2,1]  (right shift 2)
    Row 3: [s3,0  s3,1  s3,2  s3,3] -> [s3,1  s3,2  s3,3  s3,0]  (right shift 3)
    
    Args:
        state: 4x4 state matrix (list of lists)
    
    Returns:
        Shifted 4x4 state matrix
    """
    result = [
        state[0][:],                                    # Row 0: no shift
        state[1][-1:] + state[1][:-1],                  # Row 1: right shift 1
        state[2][-2:] + state[2][:-2],                  # Row 2: right shift 2
        state[3][-3:] + state[3][:-3]                   # Row 3: right shift 3
    ]
    return result


if __name__ == "__main__":
    # Test InvShiftRows
    # Use ShiftRows output as input
    test_state = [
        [0xd4, 0xe0, 0xb8, 0x1e],
        [0xbf, 0xb4, 0x41, 0x27],  # This is the result after left shift 1
        [0x5d, 0x52, 0x11, 0x98],  # This is the result after left shift 2
        [0x30, 0xae, 0xf1, 0xe5]   # This is the result after left shift 3
    ]
    
    result = inv_shift_rows(test_state)
    
    print("InvShiftRows Test:")
    print("Input state matrix:")
    for i, row in enumerate(test_state):
        print(f"Row {i}: {[hex(b) for b in row]}")
    
    print("\nOutput state matrix:")
    for i, row in enumerate(result):
        print(f"Row {i}: {[hex(b) for b in row]}")
    
    # Verify inverse operation
    print("\nVerification (should restore original rows):")
    print(f"Row 0 unchanged: {test_state[0] == result[0]}")
    print(f"Row 1 right shift 1: original [0x27, 0xbf, 0xb4, 0x41] -> {[hex(b) for b in result[1]]}")
    print(f"Row 2 right shift 2: original [0x11, 0x98, 0x5d, 0x52] -> {[hex(b) for b in result[2]]}")
    print(f"Row 3 right shift 3: original [0xae, 0xf1, 0xe5, 0x30] -> {[hex(b) for b in result[3]]}")
