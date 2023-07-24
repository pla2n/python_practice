#import sys
#import heapq
#L = []
#WL = []
#result = 0
#N, K = map(int, sys.stdin.readline().split())

#for i in range(N):
#    heapq.heappush(L, list(map(int, sys.stdin.readline().split())))

#for i in range(K):
#    WL.append(int(sys.stdin.readline()))

#WL.sort()
#heap=[]
#for w in WL:
#    while L and L[0][0] <= w:
#        heapq.heappush(heap, -heapq.heappop(L)[1])
#    if heap:
#        print(heap)
#        result -= heapq.heappop(heap)
#    elif not L:
#        break
#print(result)

import sys
import heapq
input = sys.stdin.readline
N, K = map(int, input().split())
L = []
C = []
[heapq.heappush(L, list(map(int, input().split()))) for i in range(N)]
[heapq.heappush(C, int(input())) for i in range(K)]

C.sort()
heap = []
result = 0
for w in C:
    while L and L[0][0] <= w:
        heapq.heappush(heap, -heapq.heappop(L)[1])
    if heap:
        result -= heapq.heappop(heap)
    elif not L:
        break
print(result)