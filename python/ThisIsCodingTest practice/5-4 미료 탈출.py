from collections import deque
import sys
input = sys.stdin.readline

n, m = map(int, input().split())
L = [list(map(int, input().strip())) for _ in range(n)]

dx = [1, 0, -1, 0]
dy = [0, 1, 0, -1]

def bfs():
    q = deque()
    q.append((0, 0))
    while q:
        x, y = q.popleft()
        for i in range(4):
            nx = x + dx[i]
            ny = y + dy[i]
            if 0 <= nx < n and 0 <= ny < m and L[nx][ny] == 1:
                L[nx][ny] += L[x][y]
                q.append((nx, ny))
                break

bfs()
print(L[n-1][m-1])

'''
5 6
101010
111111
000001
111111
111111
'''