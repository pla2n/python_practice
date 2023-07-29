import sys
input = sys.stdin.readline

N = int(input())
L = []
for i in range(N):
    L.append(int(input()))

L.sort(reverse=True)
for i in range(N):
    print(L[i], end=' ')

'''
3
15
27
12
'''