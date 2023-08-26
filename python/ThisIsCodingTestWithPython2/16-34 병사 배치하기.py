import sys
input = sys.stdin.readline

n = int(input())
L = list(map(int, input().split()))
count = 0

for i in range(1, n):
    if L[i-1] <= L[i]:
        count += 1
        L[i] = L[i-1]
    elif L[i] <= L[i+1]:
        count += 1
        L[i] = L[i-1]
