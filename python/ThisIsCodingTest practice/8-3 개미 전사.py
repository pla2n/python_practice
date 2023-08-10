import sys
input = sys.stdin.readline

n = int(input())
L = list(map(int, input().split()))

d = [0] * (n+1)
d[0] = L[0]
d[1] = max(L[0], L[1])

for i in range(2, n):
    d[i] = max(d[i-1], d[i-2] + L[i])
print(d[n-1])
'''
4
1 3 1 5
'''