import sys
input = sys.stdin.readline

N, M = map(int, input().split())
X, Y, D = map(int, input().split())
L = [list(map(int, input().split())) for _ in range(N)]

dx = [-1, 0, 1, 0] # 북, 동, 남, 서 에 해당하는 순서대로 방향을 전환할 수 있도록 만들어 줌
dy = [0, 1, 0, -1]
rs = 0
def game(x, y, d):
    global rs
    rs += 1 # 이동 횟수 추가
    L[x][y] = 2 # 방문 했으니 값을 2로 변경해 구분해 줌
    count = 0
    while count < 4: # 방향 전환 총 4번까지 count 이용해 4번 변경 확인
        if d == 3:
            d = 0
        else:
            d += 1
        count += 1
        nx = x + dx[d]
        ny = y + dy[d]
        if 0 <= nx < N and 0 <= ny < M and L[nx][ny] == 0: # 범위에서 벗어나지 않고 육지에 도달 한다면 이동
            game(nx, ny, d)
            break
    nx = x + dx[d-2] # 근처 4칸에 방문 하지 않은 육지가 없을 경우 뒤로 이동
    ny = y + dy[d-2]
    if 0 > nx or nx >= N or 0 > ny or ny >= M or L[nx][ny] == 1: # 뒤로 이동 했는데 만약 바다에 도착 했다면, 종료
        return

game(X, Y, D)
print(rs)

'''
4 4
1 1 0
1 1 1 1
1 0 0 1
1 1 0 1
1 1 1 1

3 3
1 1 0
1 0 0 
0 0 0
0 1 0
'''