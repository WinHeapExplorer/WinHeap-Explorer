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

import os
import sys
import subprocess


#i5: we need to implement some robust approach for heap_overflow_shareddll_loader test.
# Now it depends on addresses in sysdlls_rtn_to_instrument_test.txt and fails
# on different machines.
run_winhe_command = "pin.exe -t winhe.dll -d sysdlls_rtn_to_instrument_test.txt  "
tests = ["heap_overflow.exe", "heap_overflow_system.exe", "heap_overflow_shareddll_loader.exe"]
#test results signature
sign_dict = dict()
                                 #HoF,#HoR,#HuF,HuR,UAF
sign_dict["heap_overflow.exe"] = [4, 4, 3, 3, 2]
sign_dict["heap_overflow_system.exe"] = [2, 4, 2, 2, 18]
sign_dict["heap_overflow_shareddll_loader.exe"] = [6, 8, 5, 5, 2]
for test in tests:
    exec_line = run_winhe_command + "-o " + test + ".txt -- " + test
    print exec_line
    subprocess.call(exec_line)
    
# check results
for test in tests:
    hof = 0
    hor = 0
    huf = 0
    hur = 0
    uaf = 0
    content = open(test+".txt", 'r').readlines()
    for line in content:
        flag = 0
        if "heap overflow" in line:
            hof += 1
        if "heap underflow" in line:
            huf += 1
        if "heap overrun" in line:
            hor += 1
        if "heap underrun" in line:
            hur += 1
        if "use after free" in line:
            uaf += 1
    sign_list = sign_dict[test]
    if sign_list[0] != hof:
        print "HoF for " + test + " is different"
        flag = 1
    if sign_list[1] != hor:
        print "HoR for " + test + " is different"
        flag = 1
    if sign_list[2] != huf:
        print "HuF for " + test + " is different"
        flag = 1
    if sign_list[3] != hur:
        print "HuR for " + test + " is different"
        flag = 1
    if sign_list[4] != uaf:
        print "UAF for " + test + " is different"
        flag = 1
    if flag == 1:
        print test + " failed"
    else:
        print test + " succeed"