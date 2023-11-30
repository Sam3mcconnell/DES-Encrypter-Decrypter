/**
    @file DES.h
    @author Samuel McConnell (semcconn)
    Header for the DES Implementation.
*/

#include "DESMagic.h"

/** Number of bits in a byte. */
#define BYTE_SIZE 8

/** Round a number of bits up to the nearest number of bytes needed
    to store that many bits. */
#define ROUND_TO_BYTES(bits) (((bits) + BYTE_SIZE - 1) / BYTE_SIZE)

/** Number of bytes in a DES block. */
#define BLOCK_BYTES ROUND_TO_BYTES(BLOCK_BITS)

/** Number of bytes in the left or right halves of a block (L and R). */
#define BLOCK_HALF_BYTES ROUND_TO_BYTES(BLOCK_HALF_BITS)

/** Number of bytes to store the left-side and right-side values (C
    and D) used to create the subkeys. */
#define SUBKEY_HALF_BYTES ROUND_TO_BYTES(SUBKEY_HALF_BITS)

/** Number of bytes to store a whole subkey (K_1 .. K_16). */
#define SUBKEY_BYTES ROUND_TO_BYTES(SUBKEY_BITS)

/** Type used to represent a block to encrypt or decrypt with DES. */
typedef struct
{
    /** Sequence of bytes in the block. */
    byte data[BLOCK_BYTES];

    /** Number of bytes currently in the data array (e.g., the last block in a file could
        be shorter. */
    int len;
} DESBlock;

/**
 * This function checks the given text key to make sure it’s not too long. It copies
 * the characters of this key from textKey to the key array and pads with zero bytes up
 * to the length of a DES block.
 * @param key as the destination for the block key
 * @param textKey as the text key
 */
void prepareKey(byte key[BLOCK_BYTES], char const *textKey);

/**
 * This function returns zero or one based on the value of the bit at index
 * idx in the given array of bytes. For example, getbit( data, 1 ) should return 1
 * if the high-order bit of the first byte of data is set. This function, and the next
 * one will make it very easy to perform the bit manipulation used by the DES algorithm.
 * @param data as the array of bytes to get the bit from.
 * @param idx the index of the bit to get from the data array.
 * @return the bit at the given index of the data array.
 */
int getBit(byte const data[], int idx);

/**
 * This function clears (if val is zero) or sets (if val is one) the bit at index
 * idx of the data array. For example, putBit( data, 2, 0 ) will clear the
 * second-highest-order bit in the first byte of the data array.
 * @param data as the array to put the bit
 * @param idx as the index to put the bit
 * @param val as the value (0 or 1)
 */
void putBit(byte data[], int idx, int val);

/**
 * This function performs the permute operation, copying n bits from the given input
 * array to output selected by the first n elements of perm. If n isn’t multiple of 8,
 * then this function should set any remaining bits in the last byte to zero.
 * @param output as the array of bytes to put the permuted bits into.
 * @param input as the array of bytes to permute.
 * @param perm as the permutable bytes.
 * @param n as the number of elements to perm.
 */
void permute(byte output[], byte const input[], int const perm[], int n);

/**
 * This function computes 16 subkeys based on the input key and stores each one
 * in an element of the given K array. The resulting subkeys are stored in
 * K[ 1 ] .. K[ 16 ]. Element zero of the subkey array isn’t used.
 * @param K as the destination of the 16 subkeys based on the input key.
 * @param key as the inpute key.
 */
void generateSubkeys(byte K[ROUND_COUNT][SUBKEY_BYTES], byte const key[BLOCK_BYTES]);

/**
 * This function returns the result of an S-Box calculation in the four high-order bits
 * of output[ 0 ]. The idx value ranges from 0 to 7. The result is an element of sBoxTable[ idx ]
 * selected by bits idx * 6 + 1 to idx * 6 + 6 of B. Note that idx counts from zero for B1,
 * one for B2.
 * @param output as the output array of the 4 bits
 * @param input as the input array to get the 4 bits from
 * @param idx as the index ration to get the 6 bits from the input to make the 4 bits.
 */
void sBox(byte output[1], byte const input[SUBKEY_BYTES], int idx);

/**
 * This computes the f function based on the given 32-bit value R and the given
 * 48-bit subkey, S. The result is stored in the result array.
 * @param result as the array to store the reults
 * @param R 38 but value
 * @param K as the 48 bit value
 */
void fFunction(byte result[BLOCK_HALF_BYTES], byte const R[BLOCK_HALF_BYTES], byte const K[SUBKEY_BYTES]);

/**
 * This function performs the encrypt operation on the byte array in block, using
 * the subkeys in the K array. The encrypted result is stored back in the given block.
 * @param block as the 8 byte block being encrypted
 * @param K as the subkeys
 */
void encryptBlock(DESBlock *block, byte const K[ROUND_COUNT][SUBKEY_BYTES]);

/**
 * This function performs the decrypt operation on the byte array in block,
 * using the subkeys in the K array. The encrypted result is stored back in the given block.
 * @param block as the 8 byte block being decrypted
 * @param K as the subkeys
 */
void decryptBlock(DESBlock *block, byte const K[ROUND_COUNT][SUBKEY_BYTES]);
