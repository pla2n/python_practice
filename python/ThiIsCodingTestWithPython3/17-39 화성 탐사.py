import sys
import heapq
input = sys.stdin.readline
INF = int(1e9)

n, m = map(int, input().split())

distance = [INF] *(n+1)
graph = [[] * (n+1) for _ in range(n+1)]

def daikstra(start):
    q = []
    heapq.heappush(q, (0, start))
    distance[start] = 0
    while q:
        dist, now = heapq.heappop(q)
        if distance[now] < dist:
            continue
        for i in graph[now]:
            cost = dist + i[1]
            if distance[now] > cost:
                distance[i[0]] = cost
                heapq.heappush(q, (cost, i[0]))