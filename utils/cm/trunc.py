#############################################################################
# Desc: truncate or append 0's to Call Record dump to match the size provided
#       in the second argument, the optional third argument will specify the
#       name of the output file, if not provided the input file name is
#       appended with _trunc leaving the file extension intact.
# Date: 2018-03-25
# Author: szokoly@protonmail.com
#############################################################################
import os
import sys
from textwrap import wrap

if len(sys.argv) < 3:
    print('Usage: trunc <input .M file> <Call Record size> [<output .M file>]')
    sys.exit(1)

input = sys.argv[1]
outlength = int(sys.argv[2])
filename, file_ext = os.path.splitext(input)
output = filename + '_trunc' + file_ext
fdin = open(input)
fdout = open(output, 'w')
is_callrec = False
buff = []

for line in fdin:
    if is_callrec == True:
        if line.startswith('N'):
            callrec = ''.join(buff)
            callrec_len = len(callrec)
            if outlength < callrec_len:
                callrec = callrec[0:outlength * 2]
            elif outlength > callrec_len:
                callrec = callrec.ljust(outlength * 2, '0')
            for chunk in wrap(callrec, 32):
                l = ' '.join(wrap(chunk, 2))
                fdout.write(''.join(('D', '\t\t', l, '\n')))
            fdout.write(line)
            is_callrec = False
            buff[:] = []
        buff.append(''.join(line.split()[1:]))
    elif line.startswith('M') and line.split()[2] == '22':
        fdout.write(line)
        is_callrec = True
    else:
        fdout.write(line)

fdin.close()
fdout.close()
