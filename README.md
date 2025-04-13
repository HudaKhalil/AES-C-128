# Advanced Encryption Standard (AES), known as Rijndael
AES is a symmetric encryption algorithm and a block cipher. The former means that it uses the same key to encrypt and decrypt data. The sender and the receiver must both know and use the same secret encryption key.

## How AES encryption works
### AES includes three block ciphers or cryptographic keys, to encrypt and decrypt message blocks:

1. AES-128 uses a 128-bit key length.
2. AES-192 uses a 192-bit key length.
3. AES-256 uses a 256-bit key length.

[![security-aes-desig](https://iili.io/37c3Rg2.md.jpg)](https://freeimage.host/i/37c3Rg2)

Each cipher encrypts and decrypts data in blocks of 128 bits using cryptographic keys of 128, 192 and 256 bits, respectively. The 128-, 192- and 256-bit keys undergo 10, 12 and 14 rounds of encryption, respectively. A round consists of several processing steps including substitution, transposition and mixing of the plaintext input to transform it into the final ciphertext output. The more rounds there are, the harder it becomes to crack the encryption, and the safer the original information.

In this project I am going to demonstrate **128-bit block size** only as per assignment requirements.

## AES C Implementation Steps:
1) Create a GitHub Repository
2) Push local given code to GitHub
3) Create the GitHub Actions Workflow
4) Add the Python implementation as a Git submodule
5) Write a Python Test Using ctypes
6) Implementing AES Encryption.
7) Implementing AES Decryption.
8) Create unit test that will test the entire encryption and decryption process.

## High-Level AES Flow AES-128 does:

1) Initial AddRoundKey (round 0)

2) Rounds 1–9:

  - sub_bytes

  - shift_rows

  - mix_columns

  - add_round_key

3) Final Round (10):

  - sub_bytes

  - shift_rows

  - add_round_key (no mix_columns)