#import sys
#input = sys.stdin.readline

#N = int(input())
#map = [list(map(int, input().strip())) for _ in range(N)]
#check = [[False] * N for _ in range(N)]
#rs = 0
#dx = [0, 1, 0, -1]
#dy = [1, 0, -1, 0]

#def dfs(x, y):
#    global rs
#    rs += 1
#    check[x][y] = True
#    for i in range(4):
#        nx = x + dx[i]
#        ny = y + dy[i]
#        if 0 <= nx <= N-1 and 0 <= ny <= N-1:
#            if map[nx][ny] == 1 and check[nx][ny] == False:
#                dfs(nx, ny)
#    return rs
#result = []
#for i in range(N):
#    for j in range(N):
#        if map[i][j] == 1 and check[i][j] == False:
#            rs = 0
#            result.append(dfs(i, j))
#result.sort()
#print(len(result))
#for i in result:
#    print(i)

import sys
input = sys.stdin.readline

N = int(input())
L = [list(map(int, input().strip())) for _ in range(N)]
check = [[False]*N for _ in range(N)]

dx = [1, 0, -1, 0]
dy = [0, 1, 0, -1]
def dfs(x, y):
    global rs
    check[x][y] = True
    rs += 1
    for i in range(4):
        nx = x + dx[i]
        ny = y + dy[i]
        if 0 <= nx < N and 0 <= ny < N:
            if L[nx][ny] == 1 and check[nx][ny] == False:
                dfs(nx, ny)
    return rs
result = []

for i in range(N):
    for j in range(N):
        if L[i][j] == 1 and check[i][j] == False:
            rs = 0
            result.append(dfs(i, j))

result.sort()
print(len(result))
for i in result:
    print(i)