import sys
import itertools
input = sys.stdin.readline

n, m = map(int, input().split())

L = [list(map(int, input().split())) for _ in range(n)]
# array = []
# for i in range(n):
#     for j in range(m):
#         if L[i][j] == 0:
#             array.append((i, j))
# A = itertools.combinations(array, 3)
#
# dx = [0, 1, 0, -1]
# dy = [1, 0, -1, 0]
# def dfs(x, y, visited):
#     visited[x][y] = True
#     for i in range(4):
#         nx = x + dx[i]
#         ny = y + dy[i]
#         if 0 <= nx < n and 0 <= ny < m and visited[nx][ny] == False and (L[nx][ny] == 2 or L[nx][ny] == 0):
#             dfs(nx, ny, visited)
#
# A = itertools.combinations(array, 3)
# result = []
# for a in A:
#     visited = [[False] * m for _ in range(n)]
#     L[a[0][0]][a[0][1]] = 1
#     L[a[1][0]][a[1][1]] = 1
#     L[a[2][0]][a[2][1]] = 1
#     for i in range(n):
#         for j in range(m):
#             if L[i][j] == 2:
#                 dfs(i, j, visited)
#             elif L[i][j] == 1:
#                 visited[i][j] = True
#     count = 0
#     for i in range(n):
#         for j in range(m):
#             if visited[i][j] == False:
#                 count += 1
#     result.append(count)
#     L[a[0][0]][a[0][1]] = 0
#     L[a[1][0]][a[1][1]] = 0
#     L[a[2][0]][a[2][1]] = 0
# print(max(result))

L0 = []
L1 = []
L2 = []
for i in range(n):
    for j in range(m):
        if L[i][j] == 1:
            L1.append([i, j])
        elif L[i][j] == 2:
            L2.append([i, j])
        else:
            L0.append([i, j])
dx = [0, 1, 0, -1]
dy = [1, 0, -1, 0]
def dfs(x, y, visited):
    visited[x][y] = True
    for i in range(4):
        nx = x + dx[i]
        ny = y + dy[i]
        if 0 <= nx < n and 0 <= ny < m and [nx, ny] not in L1 and visited[nx][ny] == False:
            dfs(nx, ny, visited)

L = itertools.combinations(L0, 3)
result = []
for a, b, c in L:
    L1.append(a)
    L1.append(b)
    L1.append(c)
    count = 0
    visited = [[False] * m for _ in range(n)]
    for i in range(n):
        for j in range(m):
            if [i, j] in L2:
                dfs(i, j, visited)
    for i in range(n):
        for j in range(m):
            if visited[i][j] == False and [i, j] not in L1:
                count += 1
    result.append(count)
    L1.remove(a)
    L1.remove(b)
    L1.remove(c)
print(max(result))