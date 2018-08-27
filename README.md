# WinHeap-Explorer
The efficient and transparent proof-of-concept tool for heap-based bugs detection in x86 machine code for Windows applications.

# Requirements
WinHeap Explorer main module
 1. Intel pin-2.14-71313-msvc10-windows http://software.intel.com/sites/landingpage/pintool/downloads/pin-2.14-71313-msvc10-windows.zip

IDAScripts
 1. IDA disassembler (6.8 or higher) + IDAPython.
 
#Usage

<pre>
pin.exe -t winhe.dll -o results.txt -d sysdlls_ins_list -redzones_size 16 -- calc.exe
-d &lt;sysdlls_ins_list&gt; - file with a list of instructions in system or/and user dlls that should be instrumented.
-o &lt;log_file&gt; - file to save results.
-redzones_size - size of redzones to check heap out of bound access (default 8).
</pre>

A list of instructions to instrument may be obtained using the scripts provided in the IDAScript folder:
<pre>
sysdlls_parser.py [path to system dll]
usedlls_parser.py -d 2 [path to user dll]
-d &lt;depth_level&gt; - search depth level for potentially dangerous routines.
Please take a look at config.conf file to configure the scripts.
</pre>
NOTE: The IDAScripts is possible to use directly from IDAPro without wrappers specified above.
