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

extern "C"
{
  __declspec(dllexport) void test_overflow();
};

void test_overflow_systemdll() {
	const char *string_to_overflow = "123456789012";
    char *buffer2 = (char*) malloc(10);
	char *buffer = (char*)malloc(20);
	char *uaf = (char*)malloc(10);
	strncpy(buffer2, string_to_overflow, 12);
	printf("heap overflow test done (system)\n");
	strncpy(buffer, buffer2, 12);
	printf("heap overrun test done (system)\n");
	strncpy(buffer2-0x2, string_to_overflow, 10);
	printf("heap underflow test done (system)\n");
	strncpy(buffer, buffer2-0x2, 10);
	printf("heap underrun test done (system)\n");
}

void use_after_free() {
	const char *string_to_overflow = "123456789012";
	char *buffer = (char*)malloc(20);
	char *uaf = (char*)malloc(10);
	char *use_after_free = (char *)malloc(10);
	char a;
	free(use_after_free);
	use_after_free[6] = 'a';
	printf("use after free(read) test done (shared dll)\n");
	a = use_after_free[5];
	printf("use after free(write) test done (shared dll)\n");
	free(uaf);
	strncpy(uaf, string_to_overflow, 10);
	printf("heap use after free(write) test done (system dll)\n");
	strncpy(buffer, uaf, 10);
	printf("heap use after free(read) test done (system dll)\n");

	printf("all done\n");
	printf("Crash is possible\n");
}

void test_overflow_shared() {
	char a;
    char *buffer2 = (char*) malloc(10);
	for (int j = 0; j < 14; j++)
      buffer2[j] = 'v';
	printf("heap overflow test done (shared)\n");
	for (int j = 0; j < 14; j++)
		a = buffer2[j];
	printf("heap overrun test done (shared)\n");
	for(int j = 3; j > -4; j--)
		buffer2[j] = 'v';
	printf("heap underflow test done (shared)\n");
	for(int j = 3; j > -4; j--)
		a = buffer2[j];
	printf("heap underrun test done (shared)\n");
}

void test_overflow() {
	test_overflow_systemdll();
	test_overflow_shared();
	use_after_free();
}
