import sys
from collections import deque
input = sys.stdin.readline

n = int(input())
L = [0] * (n+1)
parent = [0] * (n+1)
for i in range(n):
    L[i] = list(map(int, input().split()))

def topology_sort():
    result = []
    q = deque()

    for i in range(1, n+1):
        if L[i] == 0:
            q.append(i)

    while q:
        now = q.popleft()
        result.append(now)
        if L[now] == 0:
            continue
'''
5
10 -1
10 1 -1
4 1 -1
4 3 1 -1
3 3 -1
'''