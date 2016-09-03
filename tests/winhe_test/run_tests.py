import os
import sys
import subprocess

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