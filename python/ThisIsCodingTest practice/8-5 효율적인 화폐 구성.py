import sys
input = sys.stdin.readline

n, m = map(int, input().split())
d = [10001] * (m+1)
L = []

for i in range(n):
    L.append(int(input()))

L.sort()
d[0] = 0
for l in L:
    for i in range(l, m+1):
        if d[i-l] != 10001:
            d[i] = min(d[i], d[i-l]+1)
if d[m] == 10001:
    print(-1)
else:
    print(d[m])

'''
3 4
3
5
7
'''