'''
BSD 2-Clause License

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
'''

''' This script is used to perform shared dlls parsing to get a list of potentially
    dangerous library calls and their instructions.
'''


import os
import sys
import idc
import idaapi
import idautils
from time import strftime

''' banned functions MSDN SDLC '''
list_of_banned_functions = ["strcpy", "strcpyA", "strcpyW", "wcscpy", "_tcscpy",\
                        "_mbscpy", "StrCpy", "StrCpyA", "StrCpyW", "lstrcpy", "lstrcpyA",\
                        "lstrcpyW", "_tccpy", "_mbccpy", "_ftcscpy", "strncpy", "wcsncpy",\
                        "_tcsncpy", "_mbsncpy", "_mbsnbcpy", "StrCpyN", "StrCpyNA", \
                        "StrCpyNW", "StrNCpy", "strcpynA", "StrNCpyA", "StrNCpyW", \
                        "lstrcpyn", "lstrcpynA", "lstrcpynW"]
list_of_banned_functions += ["strcat", "strcatA", "strcatW", "wcscat", "_tcscat", \
                             "_mbscat", "StrCat", "StrCatA", "StrCatW", "lstrcat", \
                             "lstrcatA", "lstrcatW", "StrCatBuff", "StrCatBuffA", \
                             "StrCatBuffW", "StrCatChainW", "_tccat", "_mbccat", \
                             "_ftcscat", "strncat", "wcsncat", "_tcsncat", "_mbsncat",\
                             "_mbsnbcat", "StrCatN", "StrCatNA", "StrCatNW", "StrNCat", \
                             "StrNCatA", "StrNCatW", "lstrncat", "lstrcatnA", \
                             "lstrcatnW", "lstrcatn"]
list_of_banned_functions += ["sprintfW", "sprintfA", "wsprintf", "wsprintfW", \
                             "wsprintfA", "sprintf", "swprintf", "_stprintf", \
                            "wvsprintf", "wvsprintfA", "wvsprintfW", "vsprintf", \
                            "_vstprintf", "vswprintf"]
list_of_banned_functions += ["wvsprintf", "wvsprintfA", "wvsprintfW", "vsprintf", \
                             "_vstprintf", "vswprintf"]
list_of_banned_functions += ["_fstrncpy", " _fstrncat", "gets", "_getts", "_gettws"]
list_of_banned_functions += ["IsBadWritePtr", "IsBadHugeWritePtr", "IsBadReadPtr", \
                             "IsBadHugeReadPtr", "IsBadCodePtr", "IsBadStringPtr"]
list_of_banned_functions += ["memcpy", "RtlCopyMemory", "CopyMemory", "wmemcpy"]

''' not recommended functions MSDN SDLC '''
list_of_not_recommended_functions = ["scanf", "wscanf", "_tscanf", "sscanf", "swscanf", \
                                     "_stscanf"]
list_of_not_recommended_functions += ["wnsprintf", "wnsprintfA", "wnsprintfW", \
                                      "_snwprintf", "snprintf", "sntprintf _vsnprintf", \
                                      "vsnprintf", "_vsnwprintf", "_vsntprintf", \
                                      "wvnsprintf", "wvnsprintfA", "wvnsprintfW"]
list_of_not_recommended_functions += ["_snwprintf", "_snprintf", "_sntprintf", "nsprintf"]
list_of_not_recommended_functions += ["_vsnprintf", "_vsnwprintf", "_vsntprintf", \
                                      "wvnsprintf", "wvnsprintfA", "wvnsprintfW"]
list_of_not_recommended_functions += ["strtok", "_tcstok", "wcstok", "_mbstok"]
list_of_not_recommended_functions += ["makepath", "_tmakepath", "_makepath", "_wmakepath"]
list_of_not_recommended_functions += ["_splitpath", "_tsplitpath", "_wsplitpath"]
list_of_not_recommended_functions += ["snscanf", "snwscanf", "_sntscanf"]
list_of_not_recommended_functions += ["_itoa", "_itow", "_i64toa", "_i64tow", \
                                      "_ui64toa", "_ui64tot", "_ui64tow", "_ultoa", \
                                      "_ultot", "_ultow"]
list_of_not_recommended_functions += ["CharToOem", "CharToOemA", "CharToOemW", \
                                      "OemToChar", "OemToCharA", "OemToCharW", \
                                      "CharToOemBuffA", "CharToOemBuffW"]
list_of_not_recommended_functions += ["alloca", "_alloca"]
list_of_not_recommended_functions += ["strlen", "wcslen", "_mbslen", "_mbstrlen", \
                                      "StrLen", "lstrlen"]
list_of_not_recommended_functions += ["ChangeWindowMessageFilter"]


''' list of functions that process input data i#6: we need more functions here '''
list_of_io_handling_functions = ['fopen', 'fread', 'fwrite', 'CreateFile', 'NtOpenFile',\
                                 'malloc', 'free', "HeapAlloc", "HeapReAlloc", "HeapFree"]

DEPTH_LEVEL = 0
WINHE_RESULTS_DIR = ""

OTHER_INSTRUCTION = 0
CALL_INSTRUCTION = 1
BRANCH_INSTRUCTION = 2
ASSIGNMENT_INSTRUCTION = 3
COMPARE_INSTRUCTION = 4
STACK_PUSH_INSTRUCTION = 5
STACK_POP_INSTRUCTION = 6
# group of assignment instructions ($5.1.1 vol.1 Intel x86 manual):
assign_instructions_general = ["mov", "cmov", "xchg", "bswap", "xadd", "ad", "sub",
                       "sbb", "imul", "mul", "idiv", "div", "inc", "dec", "neg",
                       "da", "aa", "and", "or", "xor", "not", "sar", "shr", "sal",
                       "shl", "shrd", "shld", "ror", "rol", "rcr", "rcl", "lod", "sto",\
                       "lea"]
assign_instructions_fp = ["fld", "fst", "fild", "fisp", "fistp", "fbld", "fbstp", "fxch",
                          "fcmove", "fadd", "fiadd", "fsub", "fisub", "fmul", "fimul", \
                          "fdiv", "fidiv", "fprem", "fabs", "fchs", "frndint", "fscale",\
                          "fsqrt", "fxtract", "fsin", "fcos", "fsincos", "fptan", \
                          "fpatan", "f2xm", "fyl2x", "fld", "fstcw", "fnstcw", "fldcw", \
                          "fstenv", "fnstenv", "fstsw", "fnstsw", "fxsave", "fxrstop"]
compare_instructions = ["cmp", "test"]
registers = ["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp"]
stack_push_instructions = ["push"]
stack_pop_instructions = ["pop"]
# i#7 add MMX/SSEx/AVX/64bit mode instructions.
# i#8 add tests
def GetInstructionType(instr_addr):
    instr_mnem = idc.GetMnem(instr_addr)
    if instr_mnem.startswith('call'):
        return CALL_INSTRUCTION
    elif instr_mnem.startswith('j'):
        # It seems that there is no other type of instructions
        # starting with j in x86/x86_64
        return BRANCH_INSTRUCTION
    for assign_instr_mnem in assign_instructions_general:
        if instr_mnem.startswith(assign_instr_mnem):
            return ASSIGNMENT_INSTRUCTION
    for assign_instr_mnem in assign_instructions_fp:
        if instr_mnem.startswith(assign_instr_mnem):
            return ASSIGNMENT_INSTRUCTION
    for compare_instruction in compare_instructions:
        if instr_mnem.startswith(compare_instruction):
            return COMPARE_INSTRUCTION
    for stack_push_instruction in stack_push_instructions:
        if instr_mnem.startswith(stack_push_instruction):
            return STACK_PUSH_INSTRUCTION
    for stack_pop_instruction in stack_pop_instructions:
        if instr_mnem.startswith(stack_pop_instruction):
            return STACK_POP_INSTRUCTION
    return OTHER_INSTRUCTION

def is_dangerous(name):
    global list_of_banned_functions, list_of_not_recommended_functions, \
           list_of_io_handling_functions
    for banned_function in list_of_banned_functions:
        if banned_function in name:
            return True
        elif ("_" + banned_function) in name:
            return True
    for not_recommended_func in list_of_not_recommended_functions:
        if not_recommended_func in name:
            return True
        elif ("_" + not_recommended_func) in name:
            return True
    for io_handling_function in list_of_io_handling_functions:
        if io_handling_function in name:
            return True
        elif ("_" + io_handling_function) in name:
            return True

    return False
def enumerate_function_chunks(f_start):
    """
    The function gets a list of chunks for the function.
    @f_start - first address of the function
    @return - list of chunks
    """
    # Enumerate all chunks in the function
    chunks = list()
    first_chunk = idc.FirstFuncFchunk(f_start)
    chunks.append((first_chunk, idc.GetFchunkAttr(first_chunk, idc.FUNCATTR_END)))
    next_chunk = first_chunk
    while next_chunk != 0xffffffffL:
        next_chunk = idc.NextFuncFchunk(f_start, next_chunk)
        if next_chunk != 0xffffffffL:
            chunks.append((next_chunk, idc.GetFchunkAttr(next_chunk, idc.FUNCATTR_END)))
    return chunks

def get_call_name(head):
    instruction_type = GetInstructionType(head)
    if instruction_type == CALL_INSTRUCTION:
        opnd = idc.GetOpnd(head, 0)
        if opnd not in registers:
            opnd = opnd.replace("ds:","")
            return opnd
        else:
            opnd = idc.GetDisasm(head)
            opnd = opnd[opnd.find(";") + 1:]
            opnd = opnd.replace(" ", "")
            if opnd != None:
                return opnd
    return None
def get_list_of_function_instr(addr):
    f_start = addr
    f_end = idc.FindFuncEnd(addr)
    chunks = enumerate_function_chunks(f_start)
    list_of_addr = list()
    list_of_calls = list()
    image_base = idaapi.get_imagebase(addr)
    for chunk in chunks:
        for head in idautils.Heads(chunk[0], chunk[1]):
            # If the element is an instruction
            if head == hex(0xffffffffL):
                raise Exception("Invalid head for parsing")
            if idc.isCode(idc.GetFlags(head)):
                call_name = get_call_name(head)
                if call_name != None:
                    list_of_calls.append(call_name)
                head = head - image_base
                head = str(hex(head))
                head = head.replace("L", "")
                head = head.replace("0x", "")
                list_of_addr.append(head)
    return list_of_addr, list_of_calls

def enumerate_function_names():
    func_name = dict()
    for seg_ea in idautils.Segments():
        # For each of the functions
        function_ea = seg_ea
        while function_ea != 0xffffffffL:
            function_name = idc.GetFunctionName(function_ea)
            # if already analyzed
            if func_name.get(function_name, None) != None:
                function_ea = idc.NextFunction(function_ea)
                continue
            image_base = idaapi.get_imagebase(function_ea)
            addr = function_ea - image_base
            addr = str(hex(addr))
            addr = addr.replace("L", "")
            addr = addr.replace("0x", "")
            func_name[function_name] = get_list_of_function_instr(function_ea)
            function_ea = idc.NextFunction(function_ea)
    return func_name


def search_callers(func_names, function_name, depth_level):
    sublist_of_instr = list()
    sublist_of_func_names = list()
    if depth_level > 0:
        for search_func_name in func_names:
            if search_func_name == function_name:
                continue
            list_of_instrs, list_of_funcs = func_names[search_func_name]
            if function_name in list_of_funcs:
                for instr in list_of_instrs:
                    sublist_of_instr.append(instr)
                sublist_of_func_names.append(function_name)
                result = search_callers(func_names, search_func_name, depth_level-1)
                for instr in result[0]:
                    sublist_of_instr.append(instr)
                for func_name in result[1]:
                    sublist_of_func_names.append(func_name)
    return sublist_of_instr, sublist_of_func_names
def search_in_depth(func_names, list_of_callees, depth_level):
    sublist_of_instr = list()
    sublist_of_func_names = list()
    if depth_level > 0:
        for callee in list_of_callees:
            list_of_instrs, list_of_calls = func_names.get(callee, (None, None))
            if list_of_calls == None:
                continue
            for instr in list_of_instrs:
                sublist_of_instr.append(instr)
            result = search_in_depth(func_names, list_of_calls, depth_level-1)
            for instr in result[0]:
                sublist_of_instr.append(instr)
            for func_name in result[1]:
                sublist_of_func_names.append(func_name)
    return sublist_of_instr, sublist_of_func_names

def search_dangerous_functions():
    global DEPTH_LEVEL
    func_names = dict()
    lists_of_instrs = list()
    list_of_func_names = list()
    func_names = enumerate_function_names()
    # get functions that should be instrumented
    for function_name in func_names:
        flag = 0
        list_of_instr, list_of_calls = func_names[function_name]
        for call in list_of_calls:
            if is_dangerous(call):
                flag = 1
        if flag == 1:
            list_of_func_names.append(function_name)
            lists_of_instrs.append(list_of_instr)
            #search callers
            sublists_of_instrs, sublist_of_func_names = search_callers(func_names,\
                                                                       function_name, \
                                                                       DEPTH_LEVEL)
            for sublist_of_instrs in sublists_of_instrs:
                lists_of_instrs.append(sublist_of_instrs)
            for sub_func_name in sublist_of_func_names:
                list_of_func_names.append(sub_func_name)
            #search in depth
            sublists_of_instrs, sublist_of_func_names = search_in_depth(func_names, \
                                                                        list_of_calls, \
                                                                        DEPTH_LEVEL)
            for sublist_of_instrs in sublists_of_instrs:
                lists_of_instrs.append(sublist_of_instrs)
            for sub_func_name in sublist_of_func_names:
                list_of_func_names.append(sub_func_name)
    return lists_of_instrs,list_of_func_names

def get_unique(lists_of_instr):
    result_list = list()
    for list_of_instr in lists_of_instr:
        for instr in list_of_instr:
            if instr not in result_list:
                result_list.append(instr)
    return result_list

def get_unique_names(list_of_func_names):
    result_list = list()
    for name in list_of_func_names:
        if name not in result_list:
            result_list.append(name)
    return result_list

def save_results(lists_of_instr, list_of_func_names):
    one_file = "userdlls_instr_to_instrument.txt"
    analyzed_file = idc.GetInputFile()
    analyzed_file = analyzed_file.replace(".","_")
    current_time = strftime("%Y-%m-%d_%H-%M-%S")
    file_name = WINHE_RESULTS_DIR + "\\" + one_file
    file_log = WINHE_RESULTS_DIR + "\\" + analyzed_file + "_" + current_time + ".txt"

    file = open(file_name, 'a')
    log = open(file_log, 'w')
    analyzed_file = analyzed_file.lower()
    list_of_instr = get_unique(lists_of_instr)
    list_of_func_names = get_unique_names(list_of_func_names)
    for instr in list_of_instr:
        file.write(idaapi.get_input_file_path().lower() + "!" + str(instr) + "\n")
    log.write(str(len(list_of_func_names)) + "\n")
    for name in list_of_func_names:
        log.write(name + "\n")
        print name

    file.close()
    log.close()

def init_analysis():
    results = search_dangerous_functions()
    save_results(results[0], results[1])
    print "Sucessfully done"

def main():
    global DEPTH_LEVEL, WINHE_RESULTS_DIR
    print "Start analysis"
    idc.Wait() #wait while ida finish analysis
    DEPTH_LEVEL = os.getenv('DEPTH_LEVEL')
    auto_mode = 0
    if DEPTH_LEVEL == None:
        DEPTH_LEVEL = 1 #default DEPTH_LEVEL
    else:
        DEPTH_LEVEL = int(DEPTH_LEVEL)
        auto_mode = 1
    # set WINHE_RESULTS_DIR variable in the cmd in case if you want to run IDA in the
    # silent mode.
    WINHE_RESULTS_DIR = os.getenv('WINHE_RESULTS_DIR')
    if WINHE_RESULTS_DIR == None:
        WINHE_RESULTS_DIR = os.getcwd()
    print "saving results in ", WINHE_RESULTS_DIR
    print "depth level = ", DEPTH_LEVEL
    init_analysis()
    if auto_mode == 1:
        Exit(0)

if __name__ == "__main__":
    main()

