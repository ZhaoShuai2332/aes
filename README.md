# AES Encryption/Decryption Staged Implementation

A staged implementation of AES (Advanced Encryption Standard) algorithm in Python.

## Project Structure

```
aes/
├── encryption/                  # Encryption module directory
│   ├── __init__.py             # Module initialization
│   ├── key_expansion.py        # Stage 1: Key Expansion
│   ├── add_round_key.py        # Stage 2: AddRoundKey
│   ├── sub_bytes.py            # Stage 3: SubBytes
│   ├── shift_rows.py           # Stage 4: ShiftRows
│   └── mix_columns.py          # Stage 5: MixColumns
│
├── decryption/                  # Decryption module directory
│   ├── __init__.py             # Module initialization
│   ├── key_expansion.py        # Stage 1: Key Expansion (reuses encryption module)
│   ├── add_round_key.py        # Stage 2: AddRoundKey
│   ├── inv_sub_bytes.py        # Stage 3: InvSubBytes
│   ├── inv_shift_rows.py       # Stage 4: InvShiftRows
│   └── inv_mix_columns.py      # Stage 5: InvMixColumns
│
├── aes_ex/                      # Exercise solutions
│   ├── solve_aes.py            # Detailed solution with step-by-step output
│   └── res.txt                 # Solution output results
│
├── aes_encrypt.py              # Encryption main entry point
├── aes_decrypt.py              # Decryption main entry point
└── README.md                   # Project documentation
```

## Algorithm Description

### AES-128 Encryption Flow

1. **Key Expansion**: Expand 128-bit key to 11 round keys
2. **Initial AddRoundKey**: XOR state matrix with round key 0
3. **9 Standard Rounds**:
   - SubBytes: S-box byte substitution
   - ShiftRows: Circular left shift of rows
   - MixColumns: Column matrix multiplication
   - AddRoundKey: XOR with round key
4. **Final Round** (no MixColumns):
   - SubBytes
   - ShiftRows
   - AddRoundKey

### AES-128 Decryption Flow

1. **Key Expansion**: Same as encryption
2. **Initial AddRoundKey**: Use round key 10
3. **9 Inverse Rounds**:
   - InvShiftRows: Circular right shift of rows
   - InvSubBytes: Inverse S-box substitution
   - AddRoundKey: XOR with round key
   - InvMixColumns: Inverse column matrix multiplication
4. **Final Round** (no InvMixColumns):
   - InvShiftRows
   - InvSubBytes
   - AddRoundKey (use round key 0)

## Usage

### Encryption

```python
from aes_encrypt import encrypt, encrypt_block

# Single block encryption (16 bytes)
key = b"ThisIsASecretKey"  # 16-byte key
plaintext = bytes([0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                   0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34])
ciphertext = encrypt_block(plaintext, key)

# Arbitrary length encryption (with PKCS7 padding)
message = b"Hello, AES!"
encrypted = encrypt(message, key)
```

### Decryption

```python
from aes_decrypt import decrypt, decrypt_block

# Single block decryption (16 bytes)
plaintext = decrypt_block(ciphertext, key)

# Arbitrary length decryption (removes PKCS7 padding)
decrypted = decrypt(encrypted, key)
```

### Run Tests

```bash
# Test encryption
python aes_encrypt.py

# Test decryption
python aes_decrypt.py

# Run exercise solution
python aes_ex/solve_aes.py
```

## Stage File Descriptions

### Encryption Module (encryption/)

| File | Stage | Function |
|------|-------|----------|
| `key_expansion.py` | Stage 1 | Key expansion, generates 11 round keys |
| `add_round_key.py` | Stage 2 | XOR state with round key |
| `sub_bytes.py` | Stage 3 | S-box non-linear byte substitution |
| `shift_rows.py` | Stage 4 | Circular left shift of rows |
| `mix_columns.py` | Stage 5 | GF(2^8) column matrix multiplication |

### Decryption Module (decryption/)

| File | Stage | Function |
|------|-------|----------|
| `key_expansion.py` | Stage 1 | Reuses encryption module's key expansion |
| `add_round_key.py` | Stage 2 | XOR state with round key (same as encryption) |
| `inv_sub_bytes.py` | Stage 3 | Inverse S-box byte substitution |
| `inv_shift_rows.py` | Stage 4 | Circular right shift of rows |
| `inv_mix_columns.py` | Stage 5 | GF(2^8) inverse column matrix multiplication |

## Test Verification

Using FIPS 197 standard test vectors:

| Item | Value |
|------|-------|
| Key | `2b7e151628aed2a6abf7158809cf4f3c` |
| Plaintext | `3243f6a8885a308d313198a2e0370734` |
| Expected Ciphertext | `3925841d02dc09fbdc118597196a0b32` |

- Encryption Test: PASS
- Decryption Test: PASS
- Round-trip Test: PASS
