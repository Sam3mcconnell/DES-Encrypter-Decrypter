/**
    @file DES.c
    @author Samuel McConnell (semcconn)
    This is where the DES algorithms for encryption and decryption are implemented.
    It’s broken up into several small functions for the various steps, so these can
    be tested and debugged independently.
*/

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "DES.h"

/** Number to get the right block size of any give bit size */
#define BLOCK_SIZE_GET 7

/**
 * This functions shifts bits to the left and in a circular motion
 * @param block as the bits to shift
 * @param size as the number of bits to shift
 * @param shifts as the number of shifts to perform
 */
static void shiftBits(byte block[], int size, int shifts)
{
    int blockSize = (size + BLOCK_SIZE_GET) / BYTE_SIZE;
    byte temp[size];
    memcpy(temp, block, blockSize);
    for (int j = 0; j < shifts; j++)
    {
        for (int i = size; i > 0; i--)
        {
            int value = getBit(block, i);
            if (i == 1)
            {
                putBit(temp, size, value);
            }
            else
            {
                putBit(temp, i - 1, value);
            }
        }
        memcpy(block, temp, blockSize);
    }
}

void prepareKey(byte key[BLOCK_BYTES], char const *textKey)
{
    size_t textKeyLength = strlen(textKey);

    if (textKeyLength > BLOCK_BYTES)
    {
        fprintf(stderr, "Key too long\n");
        exit(EXIT_FAILURE);
    }
    strcpy((char *)key, textKey);
    for (size_t i = textKeyLength; i < BLOCK_BYTES; ++i)
    {
        key[i] = 0x00;
    }
}

int getBit(byte const data[], int idx)
{
    idx -= 1;
    int byteIndex = idx / BYTE_SIZE;
    int bitPosition = idx % BYTE_SIZE;
    return (data[byteIndex] >> (7 - bitPosition)) & 1;
}

void putBit(byte data[], int idx, int val)
{
    idx -= 1;
    int byteIndex = idx / BYTE_SIZE;
    int bitPosition = idx % BYTE_SIZE;
    if (val == 0)
    {
        data[byteIndex] &= ~(1 << (BLOCK_SIZE_GET - bitPosition));
    }
    else
    {
        data[byteIndex] |= (1 << (BLOCK_SIZE_GET - bitPosition));
    }
}

void permute(byte output[], byte const input[], int const perm[], int n)
{
    int byteCount = (n + BLOCK_SIZE_GET) / BYTE_SIZE;

    for (int i = 0; i < byteCount; i++)
    {
        output[i] = 0;
    }
    for (int i = 0; i < n; i++)
    {
        int inputBitIndex = perm[i] - 1;
        int inputByteIndex = inputBitIndex / BYTE_SIZE;
        int inputBitOffset = inputBitIndex % BYTE_SIZE;
        int outputByteIndex = i / BYTE_SIZE;
        int outputBitOffset = i % BYTE_SIZE;
        int inputBit = (input[inputByteIndex] >> (BLOCK_SIZE_GET - inputBitOffset)) & 1;
        output[outputByteIndex] |= (inputBit << (BLOCK_SIZE_GET - outputBitOffset));
    }
}

void generateSubkeys(byte K[ROUND_COUNT][SUBKEY_BYTES], byte const key[BLOCK_BYTES])
{

    byte keyLeft[SUBKEY_HALF_BYTES], keyRight[SUBKEY_HALF_BYTES];

    permute(keyLeft, key, leftSubkeyPerm, SUBKEY_HALF_BITS);
    permute(keyRight, key, rightSubkeyPerm, SUBKEY_HALF_BITS);

    for (int round = 1; round < ROUND_COUNT; round++)
    {
        int shift = subkeyShiftSchedule[round];

        shiftBits(keyRight, SUBKEY_HALF_BITS, shift);
        shiftBits(keyLeft, SUBKEY_HALF_BITS, shift);
        byte tempRight[SUBKEY_HALF_BYTES], tempLeft[SUBKEY_HALF_BYTES];
        memcpy(tempRight, keyRight, SBOX_ROWS);
        memcpy(tempLeft, keyLeft, SBOX_ROWS);
        byte subkey[SUBKEY_BYTES];

        for (int i = 1; i <= SUBKEY_HALF_BITS; i++)
        {
            putBit(subkey, i, getBit(tempLeft, i));
            putBit(subkey, i + SUBKEY_HALF_BITS, getBit(tempRight, i));
        }

        byte permutedSubkey[SUBKEY_BYTES];
        permute(permutedSubkey, subkey, subkeyPerm, SUBKEY_BITS);

        memcpy(K[round], permutedSubkey, (SUBKEY_BITS / BYTE_SIZE));
    }
}

void sBox(byte output[1], byte const input[SUBKEY_BYTES], int idx)
{
    int startBit = idx * SBOX_INPUT_BITS + 1;
    int endBit = idx * SBOX_INPUT_BITS + SBOX_INPUT_BITS;

    byte b[SBOX_INPUT_BITS];
    int count = 1;
    for (int i = startBit; i <= endBit; i++)
    {
        putBit(b, count, getBit(input, i));
        count++;
    }
    int rowIndex = (getBit(b, 1) << 1) | getBit(b, SBOX_INPUT_BITS);
    int colIndex = 0;
    for (int i = 2; i <= SBOX_INPUT_BITS - 1; ++i)
    {
        colIndex = (colIndex << 1) | getBit(b, i);
    }

    byte value = sBoxTable[idx][rowIndex][colIndex];
    value = value << 4;
    output[0] = value;
}

void fFunction(byte result[BLOCK_HALF_BYTES], byte const R[BLOCK_HALF_BYTES], byte const K[SUBKEY_BYTES])
{
    byte expandedR[SUBKEY_BITS];
    permute(expandedR, R, expandedRSelector, SUBKEY_BITS);
    byte B[SUBKEY_BYTES];
    for (int i = 0; i < SBOX_INPUT_BITS; i++)
    {
        B[i] = expandedR[i] ^ K[i];
    }

    byte sBoxOut[SUBKEY_BITS];
    byte sBoxPutTogether[SUBKEY_BITS];
    for (int i = 0; i < SBOX_COUNT; ++i)
    {
        sBox(sBoxOut, B, i);
        for (int j = 1; j <= SBOX_OUTPUT_BITS; j++)
        {
            putBit(sBoxPutTogether, j + (i * SBOX_OUTPUT_BITS), getBit(sBoxOut, j));
        }
    }

    permute(result, sBoxPutTogether, fFunctionPerm, BLOCK_HALF_BITS);
}

void encryptBlock(DESBlock *block, byte const K[ROUND_COUNT][SUBKEY_BYTES])
{
    byte left[BLOCK_HALF_BYTES], right[BLOCK_HALF_BYTES], temp[BLOCK_HALF_BYTES];
    permute(left, block->data, leftInitialPerm, BLOCK_HALF_BITS);
    permute(right, block->data, rightInitialPerm, BLOCK_HALF_BITS);

    for (int round = 1; round < ROUND_COUNT; round++)
    {
        memcpy(temp, right, SBOX_OUTPUT_BITS);
        byte fResult[BLOCK_HALF_BYTES];
        fFunction(fResult, right, K[round]);

        for (int i = 0; i < BLOCK_HALF_BYTES; i++)
        {
            right[i] = left[i] ^ fResult[i];
        }
        memcpy(left, temp, BLOCK_HALF_BYTES);
    }

    byte combined[SBOX_COUNT];
    for (int i = 1; i <= BLOCK_BITS; i++)
    {
        putBit(combined, i, getBit(right, i));
        putBit(combined, i + BLOCK_HALF_BITS, getBit(left, i));
    }

    permute(block->data, combined, finalPerm, BLOCK_BITS);
}

void decryptBlock(DESBlock *block, byte const K[ROUND_COUNT][SUBKEY_BYTES])
{
    byte left[BLOCK_HALF_BYTES], right[BLOCK_HALF_BYTES], temp[BLOCK_HALF_BYTES];
    permute(left, block->data, leftInitialPerm, BLOCK_HALF_BITS);
    permute(right, block->data, rightInitialPerm, BLOCK_HALF_BITS);

    for (int round = ROUND_COUNT - 1; round >= 1; round--)
    {
        memcpy(temp, right, SBOX_OUTPUT_BITS);
        byte fResult[BLOCK_HALF_BYTES];
        fFunction(fResult, right, K[round]);

        for (int i = 0; i < BLOCK_HALF_BYTES; i++)
        {
            right[i] = left[i] ^ fResult[i];
        }
        memcpy(left, temp, BLOCK_HALF_BYTES);
    }

    byte combined[SBOX_COUNT];
    for (int i = 1; i <= BLOCK_BITS; i++)
    {
        putBit(combined, i, getBit(right, i));
        putBit(combined, i + BLOCK_HALF_BITS, getBit(left, i));
    }

    permute(block->data, combined, finalPerm, BLOCK_BITS);
}