#ifndef SM3_H
#define SM3_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void lx();
void QAQ(unsigned char* out_hash);
int SM3(unsigned char* msg, unsigned int msglen, unsigned char* out_hash);

#endif