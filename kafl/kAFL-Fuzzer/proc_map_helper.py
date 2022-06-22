import sys

ip = int(sys.argv[1])
f = open("edges_uniq.lst", "r")
s = f.read()
lines = s.split('\n')[:-1]

print(f"Searching for IP={ip}...")

# from proc_maps
# 555555554000-55555555e000
# 55555575e000-55555575f000
# 55555575f000-555555be3000
fp = open("../dump/proc_maps.txt", "r")
sp = fp.read()
linesp = sp.split('\n')[:-1]

ranges = []
labels = ["sgx", "sec", "text"]

for linep in linesp:
    if "/tmp/target_executable" in linep:
        (start, end) = linep[:25].split('-')
        print(linep[:25].split('-'))
        ranges.append((int(start, 16), int(end, 16), labels.pop()))

print(ranges)

for line in lines:
    (start, end, count) = line.split(',')
    start = int(start, 16)
    end = int(end, 16)

    start_l = "unknown"
    end_l = "unknown"

    for (rs, re, rl) in ranges:
        if rs <= start < re:
            start_l = rl
        if rs <= end < re:
            end_l = rl

    print(f'{start_l:<8},{hex(start):<32} -> {end_l:<8},{hex(end)}')
