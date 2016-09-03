// heap_overflow_shareddll_loader.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

typedef void (__cdecl *MPROC)(); 

int _tmain(int argc, _TCHAR* argv[])
{
	MPROC ProcAdd;
	HMODULE hLib = LoadLibraryA("heap_overflow_shared_dll.dll");
	if (hLib != NULL) {
		ProcAdd = (MPROC) GetProcAddress(hLib, "test_overflow"); 
		if (ProcAdd != NULL) {
			ProcAdd();
		}
		else
			printf("An error occured, failed to get test_overflow routine address\n");
	}
	else
		printf("An error occured in the process of the dll loading\n");

	return 0;
}

