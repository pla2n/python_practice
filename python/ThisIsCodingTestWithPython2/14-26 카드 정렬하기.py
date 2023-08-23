import sys
import heapq
input = sys.stdin.readline

n = int(input())
q = []
[heapq.heappush(q, int(input())) for _ in range(n)]
result = 0
while len(q) > 1:
    a = heapq.heappop(q)
    b = heapq.heappop(q)
    result += a+b
    heapq.heappush(q, a+b)

print(result)