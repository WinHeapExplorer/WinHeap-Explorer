// heap_overflow_system.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
using namespace std;

int _tmain(int argc, _TCHAR* argv[])
{
	const char *string_to_overflow = "123456789012";
    char *buffer2 = (char*) malloc(10);
	char *buffer = (char*)malloc(20);
	char *uaf = (char*)malloc(10);
	printf("heap overflow test started\n");
	strncpy(buffer2, string_to_overflow, 12);
	printf("heap overrun test started\n");
	strncpy(buffer, buffer2, 12);
	printf("heap underflow test started\n");
	strncpy(buffer2-0x2, string_to_overflow, 10);
	printf("heap underrun test started\n");
	strncpy(buffer, buffer2-0x2, 10);
	printf("heap use after free(read) test started\n");
	free(uaf);
	strncpy(buffer, uaf, 10);
	printf("heap use after free(write) test started\n");
	strncpy(uaf, buffer, 10);
	printf("all done\n");
	printf("Crash expected\n");
	return 0;
}

