#from collections import deque

#import sys
#input = sys.stdin.readline

#N, M = map(int, input().split())

#map = [list(map(int, input().split())) for _ in range(N)]
#check = [[False] * M for _ in range(N)]

#dy = [0, 1, 0, -1] # dy와 dx를 사용함으로써 x축, y축 이동방향을 for i range(4) 로 검사함
#dx = [1, 0, -1, 0]

#def bfs (y, x):
#    rs = 1
#    q = deque() # que를 생성
#    q.append((y, x))
#    while q:
#        ey, ex = q.popleft()
#        for k in range(4):
#            ny = ey + dy[k]
#            nx = ex + dx[k]
#            if 0 <= ny < N and 0 <= nx < M:
#                if map[ny][nx] == 1 and check[ny][nx] == False:
#                    rs += 1
#                    check[ny][nx] = True
#                    q.append((ny, nx))
#    return rs
#count = 0
#maxv = 0
#for i in range(N):
#    for j in range(M):
#        if map[i][j] == 1 and check[i][j] == False:
#            check[i][j] = True # 방문을 했는지 안했는지
#            count += 1
#            maxv = max(maxv, bfs(i, j))

#print(count)
#print(maxv)

import sys
from collections import deque
input = sys.stdin.readline

N, M = map(int, input().split())
L = [list(map(int, input().split())) for _ in range(N)]
check = [[False]*M for _ in range(N)]

dx = [1, 0, -1, 0]
dy = [0, 1, 0, -1]

def bfs(x, y):
    rs = 1
    q = deque()
    q.append((x,y))
    while q:
        ex, ey = q.popleft()
        for i in range(4):
            nx = ex + dx[i]
            ny = ey + dy[i]
            if 0 <= nx < N and 0 <= ny < M:
                if L[nx][ny] == 1 and check[nx][ny] == False:
                    check[nx][ny] = True
                    rs += 1
                    q.append((nx, ny))
    return rs

count = 0
maxv = 0
for i in range(N):
    for j in range(M):
        if L[i][j] == 1 and check[i][j] == False:
            check[i][j] = True
            count += 1
            maxv = max(maxv, bfs(i, j))
print(count)
print(maxv)