/*
 *       Huda Ibrahim, D24126339 along with
 *       a brief description of this code.
 * Name: Huda Ibrahim, StudentID: D24126339
 * AES is a symmetric encryption algorithm and a block cipher.
 * The former means that it uses the same key to encrypt and decrypt data.
 * The sender and the receiver must both know and use the same secret encryption key.
 * This code snippet provides a skeleton implementation of the Advanced Encryption Standard (AES)
 * algorithm, specifically for encrypting and decrypting single blocks of data 128 bits block size.
 */

#include <stdlib.h>
// Any other files you need to include should go here
#include <string.h> // For memcpy
#include "rijndael.h"

/*
 * Operations used when encrypting a block
 */
// S-box used in AES ( lookup table)
static const unsigned char s_box[256] = {
    // 0     1    2    3    4    5    6    7    8    9    A    B    C    D    E    F
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};
// Step #1 each byte in this matrix is replaced with its corresponding value in the S-box.
void sub_bytes(unsigned char *block)
{
  for (int i = 0; i < BLOCK_SIZE; i++)
  {
    block[i] = s_box[block[i]];
  }
}

// Step #2 deals with the 16-byte block as a 4x4 matrix
void shift_rows(unsigned char *block)
{
  unsigned char temp;
  // Leaves Row 0 unchanged

  // Row 1: Shift left by 1
  temp = block[1];
  block[1] = block[5];
  block[5] = block[9];
  block[9] = block[13];
  block[13] = temp;

  // Row 2: Shift left by 2
  temp = block[2];
  block[2] = block[10];
  block[10] = temp;
  temp = block[6];
  block[6] = block[14];
  block[14] = temp;

  // Row 3: Shift left by 3 (or right by 1)
  temp = block[15];
  block[15] = block[11];
  block[11] = block[7];
  block[7] = block[3];
  block[3] = temp;
}

// Helper function for Step #3: Galois Field multiplication
unsigned char gmul(unsigned char a, unsigned char b)
{
  unsigned char p = 0;
  for (int i = 0; i < 8; i++)
  {
    if (b & 1)
      p ^= a;
    unsigned char hi_bit_set = a & 0x80;
    a <<= 1;
    if (hi_bit_set)
      a ^= 0x1b; // Rijndael's finite field
    b >>= 1;
  }
  return p;
}
// Step #3 It processes one column at a time,
// then It combines the four bytes in each column in a specific mathematical way
// using polynomial multiplication in a finite field.
// This step is the primary source of diffusion in AES,
// meaning it spreads the influence of each input bit across multiple output bits after several rounds.
// This makes the cipher more resistant to statistical attacks.
void mix_columns(unsigned char *block)
{
  for (int c = 0; c < 4; c++)
  { // process each column
    int col = c * 4;
    unsigned char a0 = block[col];
    unsigned char a1 = block[col + 1];
    unsigned char a2 = block[col + 2];
    unsigned char a3 = block[col + 3];

    block[col + 0] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3;
    block[col + 1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3;
    block[col + 2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3);
    block[col + 3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2);
  }
}

/*
 * Operations used when decrypting a block
 */
void invert_sub_bytes(unsigned char *block)
{
  // TODO: Implement me!
}

void invert_shift_rows(unsigned char *block)
{
  // TODO: Implement me!
}

void invert_mix_columns(unsigned char *block)
{
  // TODO: Implement me!
}

/*
 * This operation is shared between encryption and decryption
 * It XORs each byte of the current state (your 16-byte block) with the corresponding byte of the round key.
 * It used at:
 * The start (initial round)
 * After every round (sub_bytes → shift_rows → mix_columns → add_round_key)
 * The final round (without mix_columns)
 */
void add_round_key(unsigned char *block, unsigned char *round_key)
{
  for (int i = 0; i < BLOCK_SIZE; i++)
  {
    block[i] ^= round_key[i];
  }
}

/*
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the other
 */

static const unsigned char rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

// Helper functions for Step expand_key:
static void sub_word(unsigned char *word)
{
  for (int i = 0; i < 4; i++)
  {
    word[i] = s_box[word[i]];
  }
}

static void rot_word(unsigned char *word)
{
  unsigned char tmp = word[0];
  word[0] = word[1];
  word[1] = word[2];
  word[2] = word[3];
  word[3] = tmp;
}

unsigned char *expand_key(unsigned char *cipher_key)
{
  int i = 0;
  unsigned char temp[4];
  unsigned char *expanded_key = malloc(176); // 11 * 16 bytes

  // Step 1: Copy original key
  for (i = 0; i < 16; i++) {
      expanded_key[i] = cipher_key[i];
  }

  int bytes_generated = 16;
  int rcon_iteration = 1;

  while (bytes_generated < 176) {
      // Copy last 4 bytes into temp
      for (i = 0; i < 4; i++) {
          temp[i] = expanded_key[bytes_generated - 4 + i];
      }

      if (bytes_generated % 16 == 0) {
          rot_word(temp);
          sub_word(temp);
          temp[0] ^= rcon[rcon_iteration++];
      }

      for (i = 0; i < 4; i++) {
          expanded_key[bytes_generated] =
              expanded_key[bytes_generated - 16] ^ temp[i];
          bytes_generated++;
      }
  }

  return expanded_key;
}

/*
 * The implementations of the functions declared in the
 * header file should go here
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key)
{
  // Step 1: Expand the key
  unsigned char *round_keys = expand_key(key);

  // Step 2: Allocate and copy plaintext to block
  unsigned char *block = (unsigned char *)malloc(BLOCK_SIZE);
  memcpy(block, plaintext, BLOCK_SIZE);

  // Step 3: Initial round key addition
  add_round_key(block, &round_keys[0]);

  // Step 4: Rounds 1–9
  for (int round = 1; round <= 9; round++) {
      sub_bytes(block);
      shift_rows(block);
      mix_columns(block);
      add_round_key(block, &round_keys[round * 16]);
  }

  // Step 5: Final round (no mix_columns)
  sub_bytes(block);
  shift_rows(block);
  add_round_key(block, &round_keys[160]); // 10th round = 16 * 10

  // Step 6: Cleanup
  free(round_keys);

  return block;
}

unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key)
{
  // TODO: Implement me!
  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
  return output;
}
