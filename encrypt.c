/**
    @file encry.c
    @author Samuel McConnell (semcconn)
    Implementation of the DES algorithm.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>
#include "io.h"

/**
 * The function pads the 8 byte block if the block length is less than 8.
 * @param block as the block to be padded.
 */
static void padData(DESBlock *block)
{
    for (int i = block->len; i < BLOCK_BYTES; ++i)
    {
        block->data[i] = 0x00;
    }
    block->len = BLOCK_BYTES;
}

/**
 * The main function for the DES algorithm to encrypt bytes.
 * @param argc as the argument count
 * @param argv as the argument arrray
 */
int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        printf("usage: encryt <key> <input_file> <output_file>\n");
        return EXIT_FAILURE;
    }

    char *key = argv[1];
    byte keyBlock[BLOCK_BYTES];
    prepareKey(keyBlock, key);
    byte subkeys[ROUND_COUNT][SUBKEY_BYTES];
    generateSubkeys(subkeys, keyBlock);

    // Step 2: Read the Input File
    FILE *inputFile = fopen(argv[2], "rb");
    if (!inputFile)
    {
        fprintf(stderr, "%s: No such file or directory\n", argv[2]);
        exit(EXIT_FAILURE);
    }

    FILE *outputFile = fopen(argv[3], "wb");
    if (!outputFile)
    {
        fprintf(stderr, "%s: No such file or directory\n", argv[3]);
        fclose(inputFile);
        exit(EXIT_FAILURE);
    }

    DESBlock block;

    while (1)
    {
        readBlock(inputFile, &block);
        if (block.len == 0)
            break;

        if (block.len < 8)
        {
            padData(&block);
        }

        encryptBlock(&block, subkeys);
        writeBlock(outputFile, &block);
    }

    fclose(inputFile);
    fclose(outputFile);

    return EXIT_SUCCESS;
}
