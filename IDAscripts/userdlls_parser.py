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
    dangerous library calls and their instructions
'''

import os
import sys

def parse_config():
    content = open("config.conf", 'r').readlines()
    for line in content:
        if "IDA_PATH" in line:
            line = line.split("=")
            path_to_ida = line[1].replace("\n", "")
        if "SCRIPT_PATH" in line:
            line = line.split("=")
            path_to_script = line[1].replace("\n", "")
        if "RESULTS_PATH" in line:
            line = line.split("=")
            path_to_results = line[1].replace("\n", "")
    return path_to_ida, path_to_script, path_to_results
def print_error():
    print ""

def main():
    if len(sys.argv) < 3:
       print "Please specify path to dll to start analysis"
       print "Usage: userdlls_parser.py -d [depth_level] [path_to_dll]"
       return 0
    path_to_ida, path_to_script, path_to_results = parse_config()
    if sys.argv[1] == '-d':
        try:
            depth = int(sys.argv[2])
            dll_path = sys.argv[3]
        except:
            print "Failed to parse depth level count"
            print "Usage: userdlls_parser.py -d [depth_level] [path_to_dll]"
            return 0
    else:
        dll_path = sys.argv[1]
    os.system('set DEPTH_LEVEL=' + str(depth))
    os.environ["DEPTH_LEVEL"] = str(depth)
    os.environ["WINHE_RESULTS_DIR"] = path_to_results
    os.system('set WINHE_RESULTS_DIR=' + path_to_results)
    print path_to_results
    #exec_line = '"C:\Program Files (x86)\IDA 6.8\idaq.exe" -A \
    #              -OIDAPython:C:\\IDAMetrics\\IDAmetrics\\dll_parser_user.py ' + dll_path
    exec_line = '"' + path_to_ida + '" -A -OIDAPython:' + path_to_script + \
                "\\dll_parser_user.py " + dll_path
    print exec_line
    try:
        os.system(exec_line)
    except:
        print "failed to start analysis, please make sure that you have IDA installed"


if __name__ == "__main__":
    main()