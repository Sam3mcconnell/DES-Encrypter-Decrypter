/**
    @file decrypt.c
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
 * This function removes the pasdding in blocks that have 0x00 at the end.
 * @param block the block for the padding to be removed.
 */
void removePadding(DESBlock *block)
{
    int padding = 0;
    int i;

    for (i = BLOCK_BYTES - 1; i >= 0; i--)
    {
        if (block->data[i] == 0x00)
        {
            padding++;
        }
        else
        {
            break;
        }
    }
    block->len -= padding;
}

/**
 * The main function for the DES algorithm to decrypt bytes.
 * @param argc as the argument count
 * @param argv as the argument arrray
 */
int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        fprintf(stderr, "usage: decrypt <key> <input_file> <output_file>\n");
        return EXIT_FAILURE;
    }

    char *key = argv[1];
    byte keyBlock[BLOCK_BYTES];
    prepareKey(keyBlock, key);
    byte subkeys[ROUND_COUNT][SUBKEY_BYTES];
    generateSubkeys(subkeys, keyBlock);

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
        {
            break;
        }

        decryptBlock(&block, subkeys);
        removePadding(&block);
        writeBlock(outputFile, &block);
    }

    fclose(inputFile);
    fclose(outputFile);
}
