/**
    @file io.c
    @author Samuel McConnell (semcconn)
    This component is responsible for reading input
    and writing output files a block at a time.
*/

#include <stdio.h>
#include "io.h"

void readBlock(FILE *fp, DESBlock *block)
{
    block->len = 0;
    size_t bytesRead = fread(block->data, 1, BLOCK_BYTES, fp);
    block->len = bytesRead;
}

void writeBlock(FILE *fp, DESBlock const *block)
{
    fwrite(block->data, 1, block->len, fp);
}