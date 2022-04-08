#!/usr/bin/env python3
import json

def parse_bytes(n):
    xs = [n&0xFF]
    n >>= 8
    while n != 0:
        xs.append(n&0xFF)
        n >>= 8
    return xs

def val2str(n):
    s = ''
    for b in parse_bytes(n):
        s += chr(b) if b > 31 and b < 128 else '' # '\\x'+str(hex(b))
    return s

def main(path):
    with open(path, 'r') as f:
        data = json.load(f)
    for cmp in data['cmps']:
        print(cmp['header'])
        for i, log in enumerate(cmp['log']):
            v0 = val2str(log['v0'])
            v1 = val2str(log['v1'])
            if len(v0) or len(v1):
                print(f"{i:02} - /{v0}/ - /{v1}/")
            v0_128 = val2str(log['v0_128'])
            v1_128 = val2str(log['v1_128'])
            if len(v0_128) or len(v1_128):
                print(f"{i:02} - /{v0_128}/ - /{v1_128}/   (128)")

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <path-to-json>")
        sys.exit(1)
    main(sys.argv[1])
