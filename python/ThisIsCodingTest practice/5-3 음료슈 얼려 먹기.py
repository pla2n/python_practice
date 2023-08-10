import sys
input = sys.stdin.readline

n, m = map(int, input().split())
L = [list(map(int, input().strip())) for _ in range(n)]

dx = [1, 0, -1, 0]
dy = [0, 1, 0, -1]

def dfs(x, y):
    L[x][y] = 2
    for i in range(4):
        nx = x + dx[i]
        ny = y + dy[i]
        if 0 <= nx < n and 0 <= ny < m and L[nx][ny] == 0:
            dfs(nx, ny)
    return

rs = 0
for i in range(n):
    for j in range(m):
        if L[i][j] == 0:
            dfs(i, j)
            rs += 1
print(rs)

'''
4 5
00110
00011
11111
00000

15 14
00000111100000
11111101111110
11011101101110
11011101100000
11011111111111
11011111111100
11000000011111
01111111111111
00000000011111
01111111111000
00011111111000
00000001111000
11111111110011
11100011111111
11100011111111
'''