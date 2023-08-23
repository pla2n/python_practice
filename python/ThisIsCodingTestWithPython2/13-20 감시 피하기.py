import sys
import copy
import itertools
from collections import deque
input = sys.stdin.readline

n = int(input())
L = []
xL = []
for i in range(n):
    L.append(list(map(str, input().split())))
    for j in range(n):
        if L[i][j] == 'X':
            xL.append([i, j])

dx = [-1, 1, 0, 0]
dy = [0, 0, -1, 1]

def check(L, cL):
    for i in range(len(L)):
        for j in range(len(L)):
            if L[i][j] == 'S':
                if L[i][j] != cL[i][j]:
                    return False
    return True
def bfs(x, y, L):
    q = []
    q = deque()
    for i in range(4):
        q.append([x, y, i])
    while q:
        x, y, d = q.popleft()
        nx = x + dx[d]
        ny = y + dy[d]
        if 0 <= nx < n and 0 <= ny < n and L[nx][ny] != 'O':
            if L[nx][ny] == 'S':
                L[nx][ny] = 'X'
            q.append([nx, ny, d])
def solution():
    for a, b, c in list(itertools.combinations(xL, 3)):
        cL = copy.deepcopy(L)
        cL[a[0]][a[1]] = 'O'
        cL[b[0]][b[1]] = 'O'
        cL[c[0]][c[1]] = 'O'
        for i in range(n):
            for j in range(n):
                if cL[i][j] == 'T':
                    rs = bfs(i, j, cL)
        if check(L, cL):
            return True
    return False

def dfs(count):
    global a
    if count == 3:
        if bfs():
            a = 0
        return
    for i in range(n):
        for j in range(n):
            if L[i][j] == "X":
                L[i][j] = "O"
                dfs(count+1)
                L[i][j] = "X"

rs = solution()
if rs:
    print("YES")
else:
    print("NO")


# 복습시, dfs와 bfs 같이 이용할 것