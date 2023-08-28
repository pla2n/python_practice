import sys
import heapq
input = sys.stdin.readline
INF = int(1e9)

n, m = map(int, input().split())

L = [[INF] * (n+1) for _ in range(n+1)]

for i in range(1, n+1):
    for j in range(1, n+1):
        if i == j:
            L[i][j] = 0

for i in range(m):
    a, b = map(int, input().split())
    L[a][b] = 1

for k in range(n+1):
    for i in range(n + 1):
        for j in range(n + 1):
            L[i][j] = min(L[i][j], L[i][k] + L[k][j])

result = 0
for i in range(1, n+1):
    count = 0
    for j in range(1, n+1):
        if L[i][j] != INF or L[j][i] != INF: # 둘 중 하나라도 만족해야 비교 가능
            count += 1
    if count == n:
        result += 1
print(result)

'''
6 6
1 5
3 4
4 2
4 6
5 2
5 4
'''