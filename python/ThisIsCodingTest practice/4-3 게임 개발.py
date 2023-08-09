import sys
input = sys.stdin.readline

n, m = map(int, input().split())
a, b, d = map(int, input().split())
L = [list(map(int, input().split())) for _ in range(n)]

dx = [-1, 0, 1, 0]
dy = [0, 1, 0, -1]
result = 0
def game(x, y, d):
    global result
    L[x][y] = 2
    result += 1
    count = 0
    while count < 4:
        if d == 3:
            d = 0
        else:
            d += 1
        count += 1
        nx = x + dx[d]
        ny = y + dy[d]
        if 0 <= nx < n and 0 <= ny < m and L[nx][ny] == 0:
            L[nx][ny] = 2
            game(nx, ny, d)
            break
    nx = x + dx[d-2]
    ny = y + dy[d-2]
    if 0 > nx or nx >= n or 0 > ny or ny >= m or L[nx][ny] == 1:
        return
    return
game(a, b, d)
print(result)

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