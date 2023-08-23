import sys
input = sys.stdin.readline
n = int(input())
L = []
for i in range(n):
    name, a, b, c = input().split()
    L.append([int(a), int(b), int(c), name])
L = sorted(L, key=lambda x: (-x[0], x[1], -x[2], x[3]))
for l in L:
    print(l[3])