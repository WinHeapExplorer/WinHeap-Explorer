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

''' This script is used to perform system dlls parsing to get a list of potentially
    dangerous library calls and their instructions
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

WINHE_RESULTS_DIR = None

def enumerate_function_chunks(f_start):
    '''
    The function gets a list of chunks for the function.
    @f_start - first address of the function
    @return - list of chunks
    '''
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

def get_list_of_function_instr(addr):
    '''
    The function returns a list of instructions from a function
    @addr - is function entry point
    @return - list of instruction's addresses
    '''
    f_start = addr
    f_end = idc.FindFuncEnd(addr)
    chunks = enumerate_function_chunks(f_start)
    list_of_addr = list()
    image_base = idaapi.get_imagebase(addr)
    for chunk in chunks:
        for head in idautils.Heads(chunk[0], chunk[1]):
            # If the element is an instruction
            if head == hex(0xffffffffL):
                raise Exception("Invalid head for parsing")
            if idc.isCode(idc.GetFlags(head)):
                head = head - image_base
                head = str(hex(head))
                head = head.replace("L", "")
                head = head.replace("0x", "")
                list_of_addr.append(head)
    return list_of_addr

def enumerate_function_names():
    '''
    The function enumerates all functions in a dll.
    @return - dictionary {function_name : list of corresponded instructions}
    '''
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

def search_dangerous_functions():
    ''' The function searches for all potentially dangerous library calls in a module
    @ return - tuple<a list of instructions from a list of potentially dangerous libcalls,
                     a list of potentially dangerous libcalls found in a module
    '''
    global list_of_banned_functions, list_of_not_recommended_functions
    ''' key - name, value - list of (instructions - module offset) '''
    func_names = dict()
    list_of_instrs = list()
    list_of_func_names = list()

    func_names = enumerate_function_names()
    for banned_function in list_of_banned_functions:
        if banned_function in func_names:
           list_of_instrs.append(func_names[banned_function])
           print 'Found banned function ', banned_function
           list_of_func_names.append(banned_function)
           continue
        elif ("_" + banned_function) in func_names:
            list_of_instrs.append(func_names["_" + banned_function])
            print 'Found banned function ', "_" + banned_function
            list_of_func_names.append("_" + banned_function)
            continue
    for not_recommended_func in list_of_not_recommended_functions:
        if not_recommended_func in func_names:
            list_of_instrs.append(func_names[not_recommended_func])
            print 'Found not recommended function ', not_recommended_func
            list_of_func_names.append(not_recommended_func)
            continue
        elif ("_" + not_recommended_func) in func_names:
            list_of_instrs.append(func_names["_" + not_recommended_func])
            print 'Found not recommended function ', "_" + not_recommended_func
            list_of_func_names.append("_" + not_recommended_func)
            continue
    return list_of_instrs,list_of_func_names

def get_unique(lists_of_instr):
    ''' The function returns a list of unique instructions from the list of instructions
    @list_of_instr - a list of instructions
    @return a list of unique instructions
    '''
    result_list = list()
    for list_of_instr in lists_of_instr:
        for instr in list_of_instr:
            if instr not in result_list:
                result_list.append(instr)
    return result_list

def save_results(lists_of_instr, list_of_func_names):
    ''' The function saves results in a file
    @list_of_instr - a list of instructions to save_results
    @list_of_func_name - a list of functions names to save

    '''
    one_file = "sysdlls_instr_to_instrument.txt"
    analyzed_file = idc.GetInputFile()
    analyzed_file = analyzed_file.replace(".","_")
    current_time = strftime("%Y-%m-%d_%H-%M-%S")
    file_name = WINHE_RESULTS_DIR + "\\" + one_file
    file_log = WINHE_RESULTS_DIR + "\\" + analyzed_file + "_" + current_time + ".txt"

    file = open(file_name, 'a')
    log = open(file_log, 'w')
    analyzed_file = analyzed_file.lower()
    list_of_instr = get_unique(lists_of_instr)
    for instr in list_of_instr:
        file.write(idaapi.get_input_file_path().lower() + "!" + str(instr) + "\n")
    log.write(str(len(list_of_func_names)) + "\n")
    for name in list_of_func_names:
        log.write(name + "\n")

    file.close()
    log.close()

def init_analysis():
    results = search_dangerous_functions()
    save_results(results[0], results[1])


def main():
    global WINHE_RESULTS_DIR
    print "Start analysis"
    idc.Wait() #wait while ida finish analysis
    DEPTH_LEVEL = os.getenv('DEPTH_LEVEL')
    auto_mode = 0
    # set WINHE_RESULTS_DIR variable in the cmd in case if you want to run IDA in the
    # silent mode.
    WINHE_RESULTS_DIR = os.getenv('WINHE_RESULTS_DIR')
    if WINHE_RESULTS_DIR == None:
        WINHE_RESULTS_DIR = os.getcwd()
    else:
        auto_mode = 1
    print "saving results in ", WINHE_RESULTS_DIR
    init_analysis()
    if auto_mode == 1:
        Exit(0)

if __name__ == "__main__":
    main()

