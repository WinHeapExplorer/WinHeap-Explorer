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
    if len(sys.argv) < 2:
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
    #exec_line = '"C:\Program Files (x86)\IDA 6.8\idaq.exe" -A -OIDAPython:C:\\IDAMetrics\\IDAmetrics\\dll_parser_user.py ' + dll_path
    exec_line = '"' + path_to_ida + '" -A -OIDAPython:' + path_to_script + "\\dll_parser_user.py " + dll_path
    print exec_line
    try:
        os.system(exec_line)
    except:
        print "failed to start analysis, please make sure that you have IDA installed"
    

if __name__ == "__main__":
    main()