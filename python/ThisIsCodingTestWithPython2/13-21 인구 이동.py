import sys
from collections import deque
input = sys.stdin.readline

n, l, k = map(int, input().split())
L = [list(map(int, input().split())) for _ in range(n)]

dx = [-1, 1, 0, 0]
dy = [0, 0, -1, 1]

def bfs(X, Y, visited):
    q = deque()
    q.append([X, Y])
    result = []
    result.append([X, Y])
    s = L[X][Y]
    count = 1
    visited[X][Y] = True
    while q:
        x, y = q.popleft()
        for i in range(4):
            nx = x + dx[i]
            ny = y + dy[i]
            if 0 <= nx < n and 0 <= ny < n and visited[nx][ny] == False:
                if l <= abs(L[nx][ny] - L[x][y]) <= k:
                    visited[nx][ny] = True
                    result.append([nx, ny])
                    s += L[nx][ny]
                    count += 1
                    q.append([nx, ny])
    if len(result) > 1:
        for rs in result:
            L[rs[0]][rs[1]] = s // count
        return False
    else:
        return True
rs = False
count = 0
stack = 0
while True:
    visited = [[False] * n for _ in range(n)]
    stack = 0
    for i in range(n):
        for j in range(n):
            if visited[i][j] == False:
                rs = bfs(i, j, visited)
                stack += 1
    if stack == n*n:
        break
    count += 1

print(count)