/**
    @file DES.h
    @author Samuel McConnell (semcconn)
    Header for the DES Implementation.
*/

#include "DES.h"

/**
 * This function reads up to 8 bytes from the given input file, storing
 * them in the data array of block and setting the len field to indicate
 * how many bytes have been read.
 * @param fp as the file to be read
 * @param block as the data array to store the 8 bytes
 */
void readBlock(FILE *fp, DESBlock *block);

/**
 * This function writes the contents of the data array in block to the given file.
 * The len field of block indicates how many bytes the block contains.
 * @param fp as the file to be wrote to.
 * @param block as the data array that holds the 8 bytes to be written.
 */
void writeBlock(FILE *fp, DESBlock const *block);
