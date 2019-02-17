import sys
import re

if len(sys.argv) != 3:
    print 'usage: %s "<pattern1[|pattern2]>" <MST filename>' % sys.argv[0]
    sys.exit(1)

reFirstMsg = re.compile(r'\s*\d+\s*\d+:\d+:\d+')
patterns = sys.argv[1]
filename = sys.argv[2]
buffer = []
line = ''

fd = open(filename, 'rU')

while not reFirstMsg.match(line):
    line = fd.readline()
buffer.append(line)

for line in fd:
    if line.startswith('\n') and len(buffer) > 1:
        buffer.append(line)
        message = ''.join(buffer)
        for pattern in patterns.split('|'):
            if pattern in message:
                print message
                break
        buffer = []
    else:
        buffer.append(line)

fd.close()
