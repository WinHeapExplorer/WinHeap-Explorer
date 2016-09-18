BSD 2-Clause License

Copyright (c) 2013-2015,
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
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

/* TODO: description */
#define ITERATOR_DEBUG_LEVEL 0
//#include <sparsehash/internal/sparseconfig.h>
//#include <sparsehash/sparse_hash_map>
#include <fstream>
#include <iostream>
#include <sstream>
#include <map>
#include <unordered_map>
#include <algorithm>
#include <string>
#include <unordered_set>
#include "pin.H"

//#define DEBUG 1
//#define DEBUG_INSTR_RTN 1
//#define PRINT_WARNINGS 1
//#define PRINT_INSTRUCTIONS 1

UINT32 redzone_size = 0x8;

namespace WINDOWS
{
    #include <Windows.h>
    #include <excpt.h>
}
#define noop ((void)0)
/* TODO update description */
KNOB<string> KnobDllCode(KNOB_MODE_WRITEONCE, "pintool",
    "d", "sysdlls_rtn_to_instrument.txt", "specify file with a list of libcalls and instructions in shared dlls that need to be instrumented");
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "results.out", "specify output results file name");
KNOB<BOOL> KnobNoDll(KNOB_MODE_WRITEONCE,  "pintool",
    "no_dll", "1", "do not instrument code in shared dlls");
KNOB<UINT32> KnobRedZoneSize(KNOB_MODE_WRITEONCE,  "pintool",
    "redzone", "8", "redzones size");
ofstream OutFile;

/* Shadow memory test */

typedef WINDOWS::BYTE uint8_t;
static const size_t kShadowRatioLog = 3;
static const size_t kShadowRatio = (1 << kShadowRatioLog);
#define kRedzoneBit 0x80
WINDOWS::DWORD length = 0x20000000;
WINDOWS::BYTE *shadow_memory = NULL;
uint8_t kHeapAddressableMarker = 0x0;
uint8_t kHeapFreedMarker = 0x8;
uint8_t kHeapRedZoneRight = 0xf4;
uint8_t kHeapRedZoneLeft = 0xf3;


/* end */
typedef unsigned char BYTE;
#define DWORD_SIZE 0x4
#define RED_ZONE_SIZE 0x4
#define DO_NOT_REPORT_ONE_BYTE_OVERFLOW 0x1
int instructions_instrumented = 0;
PIN_LOCK lock;

/* a map of heap blocks that was allocated by app
 * first value is an address of first byte in heap
 * second value is struct, where first element is heap last address
 * and third value is a bool flag indicated whether memory was allocated
 * or freed.
 */
std::unordered_map<ADDRINT, ADDRINT> heap_blocks;
/* additional hashmap to support HeapAlloc/malloc calls 
   1 param addr where it was called
   2 param is a size to allocate
*/
std::unordered_map<ADDRINT, std::pair<ADDRINT, int>> heap_alloc_in_process;
/* a map of instructions that need to be instrumented */
std::unordered_map<ADDRINT, bool> instr_to_instrument_addr_map;

/* red zones in heap <RED_ZONE_SIZE> bytes before and after allocated memory
   first value - address of byte in redzone
   second value indicates whether red zone byte before (false) or after (true) 
   allocated piece of heap 
*/
std::unordered_map<ADDRINT, bool> heap_red_zones; 

/* hash map of shared dlls instructions that should be instrumented */
std::unordered_map<std::string, std::unordered_set<ADDRINT>> dlls_ins_to_instr_addr_map;

std::unordered_map<std::string, ADDRINT> dlls_image_bases;

bool dont_report_one_byte_overflow = false;
bool dont_report_two_bytes_overflows = false;
UINT32 size_of_freed_heap = 0;

bool IsRedzone(uint8_t marker) {
    return (marker & kRedzoneBit) == kRedzoneBit;
}
long long int malloc_count = 0;

bool IsAccessible(const void* addr, UINT32 instr_addr, bool is_write) {
  uintptr_t index = reinterpret_cast<uintptr_t>(addr);
  uintptr_t start = index & 0x7;

  index >>= kShadowRatioLog;
  if (index > length)
    return false;

  uint8_t shadow = shadow_memory[index];
  if (shadow == 0)
    return true;
  malloc_count++;
  if (IsRedzone(shadow)) {
    if (shadow == 0xf3) {
	  if (is_write)
        OutFile << "[heap underflow] accessing 0x" << hex << addr << " at 0x" << hex << instr_addr << endl;
	  else
        OutFile << "[heap underrun] accessing 0x" << hex << addr << " at 0x" << hex << instr_addr << endl;
	} else if (shadow == 0xf4) {
	  if (is_write)
        OutFile << "[heap overflow] accessing 0x" << hex << addr << " at 0x" << hex << instr_addr << endl;
	  else
        OutFile << "[heap overrun] accessing 0x" << hex << addr << " at 0x" << hex << instr_addr << endl;
	} else {
      OutFile << "heap out of bound, accessing 0x" << hex << addr << " at 0x" << hex << instr_addr << endl;
	}
    return false;
  }

  if (shadow & kHeapFreedMarker) {
    if (shadow == kHeapFreedMarker)
     OutFile << "[use after free], accessing 0x" << hex << addr << " at 0x" << hex << instr_addr << endl;
    else if (start < (kHeapFreedMarker ^ shadow))
     OutFile << "[use after free] accessing 0x" << hex << addr << " at 0x" << hex << instr_addr << endl;
    else
     return true;
  }

  if (start >= shadow) {
	if (is_write)
      OutFile << "[heap overflow] accessing 0x" << addr << " at 0x" << hex << instr_addr << endl;
	else
      OutFile << "[heap overrun] accessing 0x" << addr << " at 0x" << hex << instr_addr << endl;
  }

  return start < shadow;
}

void IsAddressRangeAcessible(const void* addr, size_t access_size, UINT32 instr_addr, bool is_write) {
  uintptr_t index = reinterpret_cast<uintptr_t>(addr);
  for (size_t i = 0; i < access_size; i++) {
    IsAccessible((void *)(index + i), instr_addr, is_write);
  }
}

void Poison(const void* addr, size_t size, uint8_t shadow_val) {
  uintptr_t index = reinterpret_cast<uintptr_t>(addr);
  uintptr_t start = index & (kShadowRatio - 1);

  index >>= kShadowRatioLog;
  if (start)
    shadow_memory[index++] = start;

  size >>= kShadowRatioLog;
  if (size == 0)
     size++;
  memset(shadow_memory + index, shadow_val, size);
}

void Unpoison(const void* addr, size_t size, uint8_t shadow_val) {
  uintptr_t index = reinterpret_cast<uintptr_t>(addr);
  size_t size_tmp = 1;
  uint8_t remainder = size & (kShadowRatio - 1);
  index >>= kShadowRatioLog;
  size >>= kShadowRatioLog;
  if (size != 0)
     size_tmp = size;
  memset(shadow_memory + index, shadow_val, size_tmp);
  uint8_t old_shadow = shadow_memory[index + size];
  if (remainder != 0)
    shadow_memory[index + size] = remainder|kHeapFreedMarker;
}

void UnpoisonLeftRedzone(const void* addr) {
  uintptr_t index = reinterpret_cast<uintptr_t>(addr);
  size_t size_tmp = 1;
  size_t size = 0x8;
  uint8_t remainder = size & (kShadowRatio - 1);
  index >>= kShadowRatioLog;
  size >>= kShadowRatioLog;
  if (size != 0)
     size_tmp = size;
  memset(shadow_memory + index, kHeapAddressableMarker, size_tmp);
  uint8_t old_shadow = shadow_memory[index + size];
  if (remainder != 0)
    shadow_memory[index + size] = remainder|kHeapFreedMarker;
}

void UnpoisonRightRedzone(const void* addr) {
  uintptr_t index = reinterpret_cast<uintptr_t>(addr);
  size_t size_tmp = 1;
  size_t size = 0x8;
  uint8_t remainder = index & (kShadowRatio - 1);
  index >>= kShadowRatioLog;
  size >>= kShadowRatioLog;
  if (size != 0)
     size_tmp = size;
  if (remainder != 0) {
    shadow_memory[index] = remainder|kHeapFreedMarker;
    index++;
  }
  memset(shadow_memory + index, kHeapAddressableMarker, size_tmp);
}

void SetupBlock(const void *mem_block, size_t size) {
    uintptr_t mem_block_tmp = reinterpret_cast<uintptr_t>(mem_block);
    uintptr_t rz_before = mem_block_tmp - 0x8;
    uintptr_t rz_after = mem_block_tmp + size;
    // Poison block of memory
    Poison(mem_block, size, kHeapAddressableMarker);
    // Poison redzone before
    Poison((void *)rz_before, 8, kHeapRedZoneLeft);
    // Poison redzone after
    Poison((void *)rz_after, 4, kHeapRedZoneRight);
}

void FreeBlock(const void *mem_block, size_t size) {
    uintptr_t mem_block_tmp = reinterpret_cast<uintptr_t>(mem_block);
    uintptr_t rz_before = mem_block_tmp - 0x8;
    uintptr_t rz_after = mem_block_tmp + size;
    /* unpoison block of memory */
    Unpoison(mem_block, size, kHeapFreedMarker);
    // remove redzone before
    UnpoisonLeftRedzone((void *)rz_before);
    // remove redzone after
    UnpoisonRightRedzone((void *)rz_after);
}

/* TODO update description */
INT32 Usage()
{
    return -1;
}

int check_access(UINT32 addr, UINT32 access_size, bool is_write);
void check_access(UINT32 addr, UINT32 instr_addr, UINT32 access_size, bool is_write) {
    IsAddressRangeAcessible((void *)addr, access_size, instr_addr, is_write);
    return ;
}

VOID WriteMem(UINT32 insAddr, UINT32 memOp, UINT32 memWriteSize, THREADID threadid)
{
  PIN_GetLock(&lock, threadid+1);
  instructions_instrumented += 1;
  UINT32 addr = memOp;
#ifdef PRINT_INSTRUCTIONS
  OutFile << "Instrumented instr Write addr " << hex << insAddr << " to " << hex << memOp << " size is " << memWriteSize << endl;
#endif
  check_access(addr, insAddr, memWriteSize, true);
  PIN_ReleaseLock(&lock);
}

VOID ReadMem(UINT32 insAddr, UINT32 memOp, UINT32 memReadSize, THREADID threadid) {
  PIN_GetLock(&lock, threadid+1);
  instructions_instrumented += 1;
#ifdef PRINT_INSTRUCTIONS
  OutFile << "Instrumented instr Read addr " << hex << memOp << "at " << hex << insAddr << endl;
#endif
  check_access(memOp, insAddr, memReadSize, false);
  PIN_ReleaseLock(&lock);
}

void print_hashmaps() {
    for (auto element = instr_to_instrument_addr_map.begin(); element != instr_to_instrument_addr_map.end(); ++element)
        OutFile << "Instruction need to be instrumented " << hex << element->first << endl;
    for (auto element = dlls_ins_to_instr_addr_map.begin(); element != dlls_ins_to_instr_addr_map.end(); ++element)
        OutFile << "Instruction need to be instrumented in shared lib " << hex << element->first << endl;
}

VOID Fini(INT32 code, VOID *v)
{
    OutFile << "-----------------------"<<endl;
    for (auto element = dlls_image_bases.begin(); element != dlls_image_bases.end(); ++element)
        OutFile << element->first << " base:" << hex << element->second << endl;

    OutFile << "instructions instrumented " << hex << instructions_instrumented << endl;
	OutFile << "heap access count " << dec << malloc_count << endl;
    OutFile.close();
}

VOID before_alloc(ADDRINT arg1, ADDRINT pHeapSize, ADDRINT retIP,  bool is_HeapAlloc, ADDRINT flags, THREADID threadid) {
    PIN_GetLock(&lock, threadid+1);
    std::pair<ADDRINT, int> container (arg1, flags);
    heap_alloc_in_process[retIP] = container;
#ifdef DEBUG
    if (is_HeapAlloc)
        OutFile << "HeapAlloc called at " << hex << retIP << " param is " << arg1 << " flags are " << flags << endl;
    else
        OutFile << "maloc called at " << hex << retIP << " param is " << arg1 << " flags are " << flags << endl;
#endif
    PIN_ReleaseLock(&lock);
}

VOID after_alloc(ADDRINT ret, ADDRINT pRetValue, ADDRINT rtn_addr, ADDRINT retIP, bool is_HeapAlloc, THREADID threadid) {
    // TODO: Handle return codes
    PIN_GetLock(&lock, threadid+1);
    unsigned int size_to_allocate = 0;
    auto element = heap_alloc_in_process.find(retIP);
    if (element != heap_alloc_in_process.end()) {
        size_to_allocate = element->second.first;
        heap_alloc_in_process.erase(element);
        if (element->second.second == 0x800000) {
            PIN_ReleaseLock(&lock);
            return;
        }
    } else {
#ifdef PRINT_WARNINGS
        OutFile << "[WARNING] unknown return from HeapAlloc " << endl;
#endif
        PIN_ReleaseLock(&lock);
        return;
    }

  if (size_to_allocate != 0 && size_to_allocate != 0xffffffff) {
     int heap_start = ret;
#ifdef DEBUG
     OutFile << "[INFO] HeapAlloc(" << size_to_allocate << ") = " << std::hex << ret << " at " << hex << retIP << std::endl;
     OutFile << "HeapAlloc boundaries is [" << hex << heap_start << ";" 
             << heap_start+size_to_allocate << "] at " << hex << retIP << " (" << hex << rtn_addr << ")" << endl;
#endif
     SetupBlock((void *)heap_start, size_to_allocate);
     heap_blocks[heap_start] = size_to_allocate;
     PIN_ReleaseLock(&lock);
     return;
  }
  PIN_ReleaseLock(&lock);
}

int realloc_after_counter = 0;
VOID Before_HeapReAlloc(ADDRINT pMem, ADDRINT size, ADDRINT pSize, ADDRINT rtn_addr, ADDRINT retIP, THREADID threadid) {
    /*TODO the same like in alloc */
#ifdef DEBUG
    OutFile << "HeapReAlloc called to realloc addr" << hex << pMem << ", size =  " << hex << size << endl;
#endif
    PIN_GetLock(&lock, threadid+1);
    if (size == 0xffffffff) {
#ifdef PRINT_WARNINGS
        OutFile << "[WARNING] Unknown size to reallocate" << endl;
#endif
        PIN_ReleaseLock(&lock);
        return;
    }
    realloc_after_counter = 0;
    std::pair<ADDRINT, int> container (size, 0x0);
    heap_alloc_in_process[retIP] = container;
    PIN_ReleaseLock(&lock);
}

VOID After_HeapReAlloc(ADDRINT ret, ADDRINT rtn_addr, ADDRINT retIP, THREADID threadid) {
    PIN_GetLock(&lock, threadid+1);
    auto element = heap_alloc_in_process.find(retIP);
    unsigned int size_to_allocate = 0;
    if (element != heap_alloc_in_process.end()) {
        size_to_allocate = element->second.first;
        heap_alloc_in_process.erase(element);
        if (element->second.second == 0x800000) {
            PIN_ReleaseLock(&lock);
            return;
        }
    } else {
#ifdef PRINT_WARNINGS
        OutFile << "[WARNING] unknown return from HeapReAlloc " << endl;
#endif
        PIN_ReleaseLock(&lock);
        return;
    }
    realloc_after_counter += 1;
    if (realloc_after_counter < 3) {
        PIN_ReleaseLock(&lock);
        return;
    }
    if (size_to_allocate != -1) {
        if (ret == 0) { 
            OutFile << "HeapReAlloc failed " << endl;
            size_to_allocate = -1;
            PIN_ReleaseLock(&lock);
            return;
        }

        auto element = heap_blocks.find(ret);
        if (element != heap_blocks.end()) {
            /* remove redzone after */
            for (int i = 1; i < RED_ZONE_SIZE + 1; i++) {
#ifdef DEBUG
                OutFile << "remove redzone after " << hex << element->second + i << endl;
#endif
                /* remove old redzones, setup new redzones */
                auto element2 = heap_red_zones.find(element->second + i);
                if (element2 == heap_red_zones.end()) {
#ifdef PRINT_WARNINGS
                    OutFile << "[WARNING] failed to find redzone for " << hex << element->second + i << endl;
#endif
                    continue;
                }
                heap_red_zones.erase(element2);
                heap_red_zones[element->first + size_to_allocate + i - 1] = true;
            }
            element->second = element->first + size_to_allocate - 1;
        } else {
#ifdef PRINT_WARNINGS
            OutFile << "[WARNING] HeapReAlloc allocates new block, but we failed to find previous !" << endl;
#endif
        }
    }
    PIN_ReleaseLock(&lock);
}

int heaps_instrumented = 0;
VOID before_free(ADDRINT heap_base, ADDRINT flags, ADDRINT pHeapHandle, ADDRINT heap_handle, ADDRINT retIP, bool is_heapfree, THREADID threadid) {
    /* TODO: the same as for alloc */
    PIN_GetLock(&lock, threadid+1);
#ifdef DEBUG
    OutFile << "Trying to RtlFreeHeap " << hex << heap_handle << "at " << hex << pHeapHandle << endl;
#endif
    if (heap_handle == 0) {
#ifdef PRINT_WARNINGS
        OutFile << "[WARNING] free zero handle " << endl;
#endif
        PIN_ReleaseLock(&lock);
        return;
    }
#ifdef DEBUG
    OutFile << "[INFO]HeapFree(" << hex << heap_handle << ") at " << std::hex
            << retIP - 0x6 << std::endl;
#endif
    auto element = heap_blocks.find(heap_handle);
    if (element != heap_blocks.end()) {
        FreeBlock((void *)heap_handle, element->second);
        heap_blocks.erase(element);
    }
#ifdef DEBUG
    else
        OutFile << "failed to find heap handle = " << heap_handle << endl;
#endif
    PIN_ReleaseLock(&lock);
}

// Pin calls this function every time a new rtn is analyzed
VOID Routine(RTN rtn, VOID *v)
{ 
    PIN_LockClient();
    IMG img = IMG_FindByAddress(RTN_Address(rtn));
    std::string module_name = IMG_Name(img);
    ADDRINT img_base = IMG_StartAddress(img);
    PIN_UnlockClient();
	std::transform(module_name.begin(), module_name.end(), module_name.begin(), ::tolower);
    
	if(!IMG_Valid(img))
      return;
    
	bool main_module = IMG_IsMainExecutable(img);
	bool system_dll = false; /* TODO for system dlls we can do manual parsing */
    //if(KnobNoDll.Value() && !IMG_IsMainExecutable(img))
      //  return;
	auto element = dlls_ins_to_instr_addr_map.find(module_name);
	std::unordered_set<ADDRINT> set_of_addrs;
    if (element == dlls_ins_to_instr_addr_map.end() && !main_module) {
		return;
	} //else
		//OutFile << "will be parsed" << module_name << endl;
	if (!main_module)
		set_of_addrs = element->second;
	if(!RTN_Valid(rtn)) {
		OutFile << "invalid rtn" << endl;
		return;
	}

    /* For each instruction in the routine */
	RTN_Open(rtn);
    for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
		if (!main_module) {
			ADDRINT addr = INS_Address(ins) - img_base;
			auto value = set_of_addrs.find(addr);
			if (value == set_of_addrs.end())
				continue;
#ifdef DEBUG_INSTR_RTN
			else
				OutFile << "Manually will be instrumented " << addr << endl;
#endif
		}
         if (INS_OperandCount(ins) > 1 && INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0)){
            INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)ReadMem,
            IARG_ADDRINT, INS_Address(ins),
            IARG_MEMORYOP_EA, 0,
            IARG_ADDRINT, INS_MemoryReadSize(ins),
            IARG_THREAD_ID,
            IARG_END);
         } else if (INS_OperandCount(ins) > 1 && INS_MemoryOperandIsWritten(ins, 0)){
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)WriteMem,
                IARG_ADDRINT, INS_Address(ins),
                IARG_MEMORYOP_EA, 0,
                IARG_ADDRINT, INS_MemoryWriteSize(ins),
                IARG_THREAD_ID,
                IARG_END);
         }
	}

    RTN_Close(rtn);
}

/*
 * Instrumentation routines
 */
VOID InstrumentManually(IMG img, std::string module_name, ADDRINT img_base) {
    PIN_LockClient();
    std::transform(module_name.begin(), module_name.end(), module_name.begin(), ::tolower);
    /* check whether the instructions in the module should be instrumented or not  */
	OutFile << "instrumenting " << module_name << endl;
	auto element = dlls_ins_to_instr_addr_map.find(module_name);
    if (element != dlls_ins_to_instr_addr_map.end())  {
		std::unordered_set<ADDRINT> instrs_set = element->second;
		for (std::unordered_set<ADDRINT>::iterator it = instrs_set.begin(); it != instrs_set.end(); ++it) {
			RTN rtn = RTN_FindByAddress(*it + img_base);
			if (rtn == RTN_Invalid()) {
//#ifdef DEBUG_INSTR_RTN
				OutFile << "skipped: " << *it + img_base << endl;
//#endif
				continue;
			}
			RTN_Open(rtn);
			OutFile << "New routine at : " << *it + img_base << endl;
			OutFile << dec << RTN_NumIns(rtn) << endl;
			// Examine each instruction in the routine.
			for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
				if (INS_OperandCount(ins) > 1 && INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0)) {
#ifdef DEBUG_INSTR_RTN
					OutFile << "(read)Manually instrumented " << module_name << " at 0x" << hex << INS_Address(ins) << endl;
#endif
					INS_InsertCall(
					ins, IPOINT_BEFORE, (AFUNPTR)ReadMem,
					IARG_ADDRINT, INS_Address(ins),
					IARG_MEMORYOP_EA, 0,
					IARG_ADDRINT, INS_MemoryReadSize(ins),
					IARG_THREAD_ID,
					IARG_END);
				} else if (INS_OperandCount(ins) > 1 && INS_MemoryOperandIsWritten(ins, 0)) {
#ifdef DEBUG_INSTR_RTN
					OutFile << "(write)Manually instrumented " << module_name << " at 0x" << hex << INS_Address(ins) << endl;
#endif
				INS_InsertCall(
					ins, IPOINT_BEFORE, (AFUNPTR)WriteMem,
					IARG_ADDRINT, INS_Address(ins),
					IARG_MEMORYOP_EA, 0,
					IARG_ADDRINT, INS_MemoryWriteSize(ins),
					IARG_THREAD_ID,
					IARG_END);
				}
			}
			// Close the RTN.
			RTN_Close(rtn);
		}
		//dlls_ins_to_instr_addr_map.erase(element);
	}
	OutFile << "done" << endl;
    PIN_UnlockClient();
}

VOID Image(IMG img, VOID *v)
{  
    string module_name = IMG_Name(img);
    ADDRINT img_base = IMG_StartAddress(img);

    auto element = dlls_image_bases.find(module_name);
    if (element == dlls_image_bases.end())
        dlls_image_bases[module_name] = img_base;
    
    //if(KnobNoDll.Value() == 1)
        //InstrumentManually(img, module_name, img_base);
    PIN_InitSymbols();
    /* instrument HeapAlloc */
    RTN allocRtn3 = RTN_FindByName(img, "RtlAllocateHeap");
    if (RTN_Valid(allocRtn3)) {
        OutFile << "Found RtlAllocateHeap at: " << std::hex << RTN_Address(allocRtn3) << endl;
        // Instrument to print the input argument value and the return value.
        RTN_Open(allocRtn3);
        RTN_InsertCall(allocRtn3, IPOINT_BEFORE, (AFUNPTR)before_alloc,
                        IARG_FUNCARG_CALLSITE_VALUE, 3,
                        IARG_FUNCARG_CALLSITE_REFERENCE, 3,
                        IARG_RETURN_IP,
                        IARG_BOOL, true,
                        IARG_FUNCARG_CALLSITE_VALUE, 2,
                        IARG_THREAD_ID,
                        IARG_END); /* to check size */ 
        RTN_InsertCall(allocRtn3, IPOINT_AFTER, (AFUNPTR)after_alloc,
                        IARG_FUNCRET_EXITPOINT_VALUE,
                        IARG_FUNCRET_EXITPOINT_REFERENCE,
                        IARG_ADDRINT, RTN_Address(allocRtn3),
                        IARG_RETURN_IP,
                        IARG_BOOL, true,
                        IARG_THREAD_ID,
                        IARG_END);  /* to check returned value */
        RTN_Close(allocRtn3);
    }
    
    // instrument HeapReAlloc
    /*
    RTN allocRtn4 = RTN_FindByName(img, "RtlReAllocateHeap");
    if (RTN_Valid(allocRtn4)) {
        OutFile << "Found RtlReAllocateHeap at: " << std::hex << RTN_Address(allocRtn4) << endl;
        // Instrument to print the input argument value and the return value.
        RTN_Open(allocRtn4);
        RTN_InsertCall(allocRtn4, IPOINT_BEFORE, (AFUNPTR)Before_HeapReAlloc,
                        IARG_FUNCARG_CALLSITE_VALUE, 3,
                        IARG_FUNCARG_CALLSITE_VALUE, 4,
                        IARG_FUNCARG_CALLSITE_REFERENCE, 4,
                        IARG_ADDRINT, RTN_Address(allocRtn4),
                        IARG_RETURN_IP,
                        IARG_THREAD_ID,
                        IARG_END); // to check size 
        RTN_InsertCall(allocRtn4, IPOINT_AFTER, (AFUNPTR)After_HeapReAlloc,
                        IARG_FUNCRET_EXITPOINT_VALUE,
                        IARG_ADDRINT, RTN_Address(allocRtn4),
                        IARG_RETURN_IP,
                        IARG_THREAD_ID,
                        IARG_END);  // to check returned value
        RTN_Close(allocRtn4);
    }*/
    
    RTN freeRtn3 = RTN_FindByName(img, "RtlFreeHeap");
    if (RTN_Valid(freeRtn3))
    {
        OutFile << "Found RtlFreeHeap at: " << std::hex << RTN_Address(freeRtn3) << endl;
        RTN_Open(freeRtn3);
        RTN_InsertCall(freeRtn3, IPOINT_BEFORE, (AFUNPTR)before_free,
                      IARG_FUNCARG_CALLSITE_VALUE, 1,
                      IARG_FUNCARG_CALLSITE_VALUE, 2,
                       IARG_FUNCARG_CALLSITE_REFERENCE, 3,
                      IARG_FUNCARG_CALLSITE_VALUE, 3,
                      IARG_RETURN_IP,
                      IARG_BOOL, false,
                      IARG_THREAD_ID,
                       IARG_END);
        RTN_Close(freeRtn3);
    }
}

bool fromDllCodeToArray (const std::string & fileName) {
  ADDRINT value;
  string line;
  std::string lib_name;
  std::stringstream ss;
  bool flag = false;
  std::ifstream InputFile(fileName.c_str(), ios::in);
  if (!InputFile.is_open())
     return false;

  while (std::getline(InputFile, line)) {
     ss << std::hex << line.substr(line.find("!") + 1);
     ss >> value;
     lib_name = line.substr(0, line.find("!"));
     std::transform(lib_name.begin(), lib_name.end(), lib_name.begin(), ::tolower);
     dlls_ins_to_instr_addr_map[lib_name].insert(value);
     ss.clear();
  }
  InputFile.close();
  OutFile << "# of manually instrumented instructions = " << dlls_ins_to_instr_addr_map.size() << endl;

  return true;
}

int main(int argc, char *argv[])
{
    if(PIN_Init(argc, argv)){
        return Usage();
    }
    PIN_InitLock(&lock);
    OutFile.open(KnobOutputFile.Value().c_str());
    shadow_memory = (WINDOWS::BYTE *)WINDOWS::VirtualAlloc(NULL, length, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (shadow_memory) {
        OutFile << "Sucessfully initialized shadow memory at " << &shadow_memory << endl;
    } else {
        OutFile << "failed to initialize shadow memory, stopping" << endl;
        return 0;
    }
    //print_hashmaps();
	std::string dlls_to_inst = KnobDllCode.Value().c_str();
	if (!dlls_to_inst.empty()) {
		if (!fromDllCodeToArray(dlls_to_inst.c_str())) {
			printf("failed to open sysdlls_rtn_to_instrument.txt");
			return -1;
		}
	}
    IMG_AddInstrumentFunction(Image, 0);
    RTN_AddInstrumentFunction(Routine, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}
