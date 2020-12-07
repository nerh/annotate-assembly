import sys

disasm_file = open(sys.argv[1], "r")
base_offset = int(sys.argv[2], 16)
m0 = sys.argv[3]
m1 = sys.argv[4]

class DissassemblyLine:
    def __init__(self, addr, line, comments):
        self.addr = addr
        self.line = line
        self.comments = comments
        self.events = {}


sources = {}

comments = []
for line in disasm_file.read().splitlines():
    striped_line = line.strip()

    if striped_line.startswith("0x"):
        offset = int(striped_line.split(":")[0].split("x")[1], 16)
        absolute_address = base_offset + offset
        sources[absolute_address] = DissassemblyLine(offset, line, comments)
        comments = []
    else:
        comments.append(line)

for line in sys.stdin:
    parts = list(filter(lambda c: len(c) > 0, line.strip().split(" ")))
    period = int(parts[0])
    metric = parts[1]
    addr = int(parts[2], 16)
    if addr not in sources:
        continue
    src = sources[addr]
    if metric not in src.events:
        src.events[metric] = period
    else:
        src.events[metric] += period

for _, v in sorted(sources.items(), key = lambda i: i[0]):
    m0val = v.events[m0] if m0 in v.events else 0
    m1val = v.events[m1] if m1 in v.events else 0
    r = m0val / (1 if m1val == 0 else m1val)
    #print(v.events)
    if len(v.comments) > 0:
        for c in v.comments:
            print('        \t        \t      \t' + c)
    output = str(m0val).rjust(8, ' ') + "\t" + str(m1val).rjust(8, " ") + "\t" + str(r).rjust(6) + "\t" + v.line
    print(output)
