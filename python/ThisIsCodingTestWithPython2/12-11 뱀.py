import sys
input = sys.stdin.readline

# n = int(input()) # 보드의 크기
# K = int(input())
# array = []
# L = [[0]*n for _ in range(n)]
# for k in range(K): # 사과의 위치
#     a, b = map(int, input().split())
#     L[a-1][b-1] = 1
# li = int(input())
# array = [list(input().split()) for _ in range(li)] # 방향 전환 타이밍
#
# dx = [0, -1, 0, 1]
# dy = [1, 0, -1, 0]
# def solution():
#     length = 1
#     stack = 0
#     x, y, d, count = 0, 0, 0, 0
#     q = [(x, y)]
#     while True:
#         count += 1
#         if array and int(array[0][0])+1 == count:
#             a = array.pop(0)[1]
#             if a == 'L':
#                 d = (d + 1) % 4
#             elif a == 'D':
#                 d = (d - 1) % 4
#         nx = x + dx[d]
#         ny = y + dy[d]
#         if 0 > nx or n <= nx or 0 > ny or n <= ny or ((nx, ny) in q): # 종료 조건
#             return count
#         elif L[nx][ny] == 1: # 사과를 먹을 경우
#             length += 1
#             L[nx][ny] = 0
#         else:
#             q.pop(0)
#         q.append((nx, ny))
#         x, y = nx, ny

n = int(input())
k = int(input())
kL = [list(map(int, input().split())) for _ in range(k)]
l = int(input())
lL = []
array = []
for i in range(l):
    a, b = input().split()
    array.append(int(a))
    lL.append([a, b])

dx = [0, -1, 0, 1] # 반시계 방향 회전
dy = [1, 0, -1, 0]
L = [[0]*n for _ in range(n)]
for i in range(n):
    for j in range(n):
        if [i+1, j+1] in kL:
            L[i][j] += 1

x = 0
y = 0
d = 0
rs = 0
dir = 0
q = [(0,0)]
while True:
    if rs in array:
        if lL.pop(0)[1] == 'L':
            d = (d+1) % 4
        else:
            if d == 0:
                d = 4
            d = (d-1) % 4
    nx = x + dx[d]
    ny = y + dy[d]
    rs += 1
    if 0 <= nx < n and 0 <= ny < n and (nx, ny) not in q:
        x = nx
        y = ny
        if L[nx][ny] == 1:
            L[nx][ny] = 0
            q.append((nx, ny))
        else:
            q.append((nx, ny))
            q.pop(0)
    else:
        break

print(rs)


'''
입력
6
3
3 4
2 5
5 3
3
3 D
15 L
17 D
출력
9
'''

'''
입력
10
4
1 2
1 3
1 4
1 5
4
8 D
10 D
11 D
13 L
출력
21
'''

'''
입력
10
5
1 5
1 3
1 2
1 6
1 7
4
8 D
10 D
11 D
13 L
출력
13
'''