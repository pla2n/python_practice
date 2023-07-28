'''
방문여부 리스트 따로 생성하지 않고, 리스트의 값을 2로 만들어 줘서 구분
dfs사용 dfs 밖의 2중 for문에서 결과값 계산
dx dy 사용으로 주변 요소들 탐색
'''

import sys
input = sys.stdin.readline

N, M = map(int, input().split())
L = [list(map(int, input().strip())) for _ in range(N)]

dx = [1, 0, -1, 0]
dy = [0, 1, 0, -1]
result = 0
def dfs(x, y):
    L[x][y] = 2
    for i in range(4):
        nx = x + dx[i]
        ny = y + dy[i]
        if 0 <= nx < N and 0 <= ny < M and L[nx][ny] == 0:
            dfs(nx, ny)
    return

for i in range(N):
    for j in range(M):
        if L[i][j] == 0:
            dfs(i, j)
            result += 1
print(result)


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