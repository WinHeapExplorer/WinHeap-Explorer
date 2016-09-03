// heap_overflow.cpp : heap overflow + double free
//

#include "stdafx.h"

const char *string_to_overflow = "12345678901234567890";

int _tmain(int argc, _TCHAR* argv[])
{
	char a;
    char *buffer2 = (char*) malloc(10);
	char *use_after_free = (char *)malloc(10);
	for (int j = 0; j < 14; j++)
      buffer2[j] = 'v';
	printf("heap overflow test done\n");
	for (int j = 0; j < 14; j++)
		a = buffer2[j];
	printf("heap overrun test done\n");
	for(int j = 3; j > -4; j--)
		buffer2[j] = 'v';
	printf("heap underflow test done\n");
	for(int j = 3; j > -4; j--)
		a = buffer2[j];
	printf("heap underrun test done\n");
	free(use_after_free);
	use_after_free[6] = 'a';
	printf("use after free(read) test done \n");
	a = use_after_free[5];
	printf("use after free(write) test done \n");
	printf("crash is possible\n");
	return 0;
}

