'''
미로찾기의 경우 먼저 나온 부모노드의 자식노드들 부터 처리를 해야하므로 dfs보단 bfs가 어울린다.
'''

import sys
from collections import deque
input = sys.stdin.readline

N, M = map(int, input().split())
L = [list(map(int, input().strip())) for _ in range(N)]

dx = [1, 0, -1, 0]
dy = [0, 1, 0, -1]
result = 0
def bfs(x, y):
    q = deque()
    q.append((x, y))
    while q:
        x, y = q.popleft()
        for i in range(4):
            nx = x + dx[i]
            ny = y + dy[i]
            if 0 <= nx < N and 0 <= ny < M and L[nx][ny] == 1:
                L[nx][ny] += L[x][y]
                q.append((nx, ny))
    return L[N-1][M-1]

print(bfs(0,0))

'''
5 6
101010
111111
000001
111111
111111
'''