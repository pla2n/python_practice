import sys

N = int(sys.stdin.readline())
L = list(map(int, sys.stdin.readline().split()))
L.sort()
result = 1
for i in L:
    if i > result:
        break
    result += i
print(result)
