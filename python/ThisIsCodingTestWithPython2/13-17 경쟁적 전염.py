import sys
from collections import deque
input = sys.stdin.readline

# n, K = map(int, input().split())
# L = []
# cell = []
# for i in range(n):
#     L.append(list(map(int, input().split())))
#     for j in range(n):
#         if L[i][j] != 0:
#             cell.append(((L[i][j], i, j)))
# S, X, Y = map(int, input().split())
# dx = [0, 1, 0, -1]
# dy = [1, 0, -1, 0]
#
# def bfs(S, X, Y):
#     q = deque(cell)
#     count = 0
#     while q:
#         if count == S:
#             break
#         for i in range(len(q)):
#             v, x, y = q.popleft()
#             for j in range(4):
#                 nx = x + dx[j]
#                 ny = y + dy[j]
#                 if 0 <= nx < n and 0 <= ny < n and L[nx][ny] == 0:
#                     L[nx][ny] = L[x][y]
#                     q.append((L[nx][ny], nx, ny))
#         count += 1
#     return L[X-1][Y-1]
#
# cell.sort()
# print(bfs(S, X, Y))

n, k = map(int, input().split())
cell = []
L = []
for i in range(n):
    L.append(list(map(int, input().split())))
    for j in range(len(L[i])):
        if L[i][j] != 0:
            cell.append((L[i][j], i, j))
S, X, Y = map(int, input().split())
cell.sort()

dx = [0, 1, 0, -1]
dy = [1, 0, -1, 0]

def dfs(S, X, Y):
    q = deque(cell)
    count = 0
    while q:
        if count == S:
            break
        for j in range(len(q)): # q의 사이즈 늘어남과 상관 없이 정해진 횟수만 반복
            v, x, y = q.popleft()
            for i in range(4):
                nx = x + dx[i]
                ny = y + dy[i]
                if 0 <= nx < n and 0 <= ny < n and L[nx][ny] == 0:
                    L[nx][ny] = L[x][y]
                    q.append((L[x][y], nx, ny))
        count += 1
    return L[X-1][Y-1]

rs = dfs(S, X, Y)
print(rs)
