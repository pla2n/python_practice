import sys
input = sys.stdin.readline

N, M = map(int, input().split())
x, y, d = map(int, input().split())

L = [list(map(int, input().split())) for _ in range(N)]

dx = [-1, 0, 1, 0] # 2좌표평면 기준으로 위, 오른쪽, 아래, 왼쪽 순서를 기준
dy = [0, 1, 0, -1]

count = 0

while 1:
    if L[x][y] == 0:
        L[x][y] = 2 # 청소한 곳은 2로 바꾸어줌
        count += 1
    sw = False
    for i in range(1, 5):
        nx = x + dx[d-i] # i를 빼줌으로써 반시계반향으로 이동
        ny = y + dy[d-i]
        if 0 <= nx < N and 0 <= ny < M:
            if L[nx][ny] == 0:
                d = (d-i+4)%4
                y = ny 
                x = nx
                sw = True
                break
    if sw == False:
        nx = x - dx[d] # 반대 방향
        ny = y - dy[d]
        if 0 <= nx < N and 0 <= ny < M:
            if L[nx][ny] == 1: # 벽이 있을 경우 정지
                break
            else:
                x = nx # 벽이 아닌경우, 반대방향에서 다시 시작
                y = ny
        else:
            break

print(count)