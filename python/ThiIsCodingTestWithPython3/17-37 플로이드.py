import sys
input = sys.stdin.readline
INF = int(1e9)

n = int(input())
m = int(input())

L = [[INF] * (n+1) for _ in range(n+1)]

for i in range(1, n+1):
    for j in range(1, n+1):
        if i == j:
            L[i][j] = 0
for i in range(m):
    a, b, c = map(int, input().split())
    L[a][b] = min(L[a][b], c)

for k in range(1, n+1):
    for i in range(1, n+1):
        for j in range(1, n+1):
            L[i][j] = min(L[i][j], L[i][k] + L[k][j])

for i in range(1, n+1):
    for j in range(1, n+1):
        if L[i][j] != INF:
            print(L[i][j], end=' ')
        else:
            print(0, end=' ')
    print()