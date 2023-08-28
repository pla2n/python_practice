import heapq
import sys
input = sys.stdin.readline
INF = int(1e9)

n, m = map(int, input().split())
L = [[] for _ in range(n+1)]
distance = [INF] * (n+1)

def daikstra(start):
    q = []
    heapq.heappush(q, (0, start))
    distance[start] = 0

    while q:
        dist, now = heapq.heappop(q)
        if dist > distance[now]:
            continue
        for i in L[now]:
            cost = dist + i[1]
            if cost < distance[i[0]]:
                distance[i[0]] = cost
                heapq.heappush(q, (cost, i[0]))
for i in range(m):
    a, b = map(int, input().split())
    L[a].append((b, 1))
    L[b].append((a, 1))

daikstra(1)

result = []
max_node = 0
max_distance = 0

for i in range(1, n+1):
    if max_distance < distance[i]:
        max_distance = distance[i]
        max_node = i
print(max_node)


'''
6 7
3 6
4 3
3 2
1 3
1 2
2 4
5 2
'''