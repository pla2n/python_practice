import sys

N, M = map(int, sys.stdin.readline().split())

L = list(map(int, sys.stdin.readline().split()))

heap = L[:N]
T = L[N:N+N]

for i in range(N, M):
    count = 0
    for j in range(len(heap)):
        if heap[j] not in T:
            count += 1
        
