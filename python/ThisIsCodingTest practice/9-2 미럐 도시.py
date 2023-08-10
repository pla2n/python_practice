import sys
input = sys.stdin.readline
INF = int(1e9)

n, m = map(int, input().split())
L = [[INF]*(n+1) for _ in range(n+1)]

for i in range(n+1):
    for j in range(n+1):
        if i == j:
            L[i][j] = 0

for i in range(m):
    a, b = map(int, input().split())
    L[a][b] = 1
    L[b][a] = 1

X, K = map(int, input().split())
for k in range(n+1):
    for i in range(n+1):
        for j in range(n+1):
            L[i][j] = min(L[i][j], L[i][k] + L[k][j])
result = L[1][K] + L[K][X]
if result >= INF:
    print("-1")
else:
    print(result)