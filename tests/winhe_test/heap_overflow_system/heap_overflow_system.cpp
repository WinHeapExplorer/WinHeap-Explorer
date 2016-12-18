/*BSD 2-Clause License

Copyright (c) 2013-2016,
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.s
*/
#include "stdafx.h"
#include <iostream>
using namespace std;

int main(int argc)
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

