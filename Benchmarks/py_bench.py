import os
import sys
import random
import string

LOOPS_COUNT = 100000

strings_dict = dict()
for i in range(0, LOOPS_COUNT):
    random_str = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(3)])
    if strings_dict.get(random_str, None) != None:
        strings_dict[random_str] += 1
    else:
         strings_dict[random_str] = 1
         
         
#for str in strings_dict:
    #print "String is %s,%d" % ( str, strings_dict[str])