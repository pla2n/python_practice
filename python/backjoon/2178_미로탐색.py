from collections import deque
import sys
input = sys.stdin.readline

N, M = map(int, input().split())
L = [list(map(int, input().strip())) for _ in range(N)]

dx = [1, 0, -1, 0]
dy = [0, 1, 0, -1]
def bfs(x, y):
	global result
	q = deque([(x, y)])
	while q:
		x, y = q.popleft()
		if x == N-1 and y == M-1:
			return L[N-1][M-1]
		for i in range(4):
			nx = x + dx[i]
			ny = y + dy[i]
			if 0 <= nx < N and 0 <= ny < M:
				if L[nx][ny] == 1:
					L[nx][ny] += L[x][y]
					q.append((nx, ny))
		for j in range(4):
			print(L[j])
		print("-------")
	return L[N-1][M-1]
result = bfs(0, 0)
print(result)