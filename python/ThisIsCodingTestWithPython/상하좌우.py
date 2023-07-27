import sys
input = sys.stdin.readline

N = int(input())
A = list(map(str, input().split()))
location = [1, 1]
for i in range(len(A)):
    if A[i] == 'L' and location[1] > 1:
        location[1] -= 1
    elif A[i] == 'R' and location[1] < N:
        location[1] += 1
    elif A[i] == 'U' and location[0] > 1:
        location[0] -= 1
    elif A[i] == 'D' and location[0] < N:
        location[0] += 1
print(location[0], location[1])

dx = [0, 0, -1, 1]
dy = [-1, 1, 0, 0]
d = ['L', 'R', 'U', 'D']
x, y = 1, 1
for a in A:
    for i in range(len(d)):
        if a == d[i]:
            nx = x + dx[i]
            ny = y + dy[i]
            break
    if 0 < nx <= N and 0 < ny <= N:
        x, y = nx, ny

print(x, y)



'''
5
R R R U D D
'''