import sys
input = sys.stdin.readline

N, M = map(int, input().split())
L = [list(map(int, input().split())) for _ in range(N)]
Min = []
for i in L:
    Min.append(min(i))
print(max(Min))

N, M = map(int, input().split())
Min = 0
for i in range(N):
    L = list(map(int, input().split()))
    Min = max(Min, min(L))
print(Min)
'''
3 3
3 1 2
4 1 4
2 2 2

2 4
7 3 1 8
3 3 3 4
'''