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

