import sys
import itertools
input = sys.stdin.readline

n, m = map(int, input().split())

L = [list(map(int, input().split())) for _ in range(n)]
array = []
for i in range(n):
    for j in range(m):
        if L[i][j] == 0:
            array.append((i, j))
A = itertools.combinations(array, 3)

dx = [0, 1, 0, -1]
dy = [1, 0, -1, 0]
def dfs(x, y, visited):
    visited[x][y] = True
    for i in range(4):
        nx = x + dx[i]
        ny = y + dy[i]
        if 0 <= nx < n and 0 <= ny < m and visited[nx][ny] == False and (L[nx][ny] == 2 or L[nx][ny] == 0):
            dfs(nx, ny, visited)

A = itertools.combinations(array, 3)
result = []
for a in A:
    visited = [[False] * m for _ in range(n)]
    L[a[0][0]][a[0][1]] = 1
    L[a[1][0]][a[1][1]] = 1
    L[a[2][0]][a[2][1]] = 1
    for i in range(n):
        for j in range(m):
            if L[i][j] == 2:
                dfs(i, j, visited)
            elif L[i][j] == 1:
                visited[i][j] = True
    count = 0
    for i in range(n):
        for j in range(m):
            if visited[i][j] == False:
                count += 1
    result.append(count)
    L[a[0][0]][a[0][1]] = 0
    L[a[1][0]][a[1][1]] = 0
    L[a[2][0]][a[2][1]] = 0
print(max(result))