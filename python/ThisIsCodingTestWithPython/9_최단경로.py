import heapq
import sys
input = sys.stdin.readline
INF = int(1e9)
## 개선된 다익스트라 알고리즘 시간 복잡도 O(ElogV) > 힙을 사용해서 속도가 빠름
n, m = map(int, input().split())
start = int(input())
L = [[] for _ in range(n+1)]
for _ in range(m):
    a, b, c = map(int, input().split())
    L[a].append((b, c))
distance = [INF] * (n+1)
def dijkstra(start):
    q = []
    heapq.heappush(q, (0, start)) # 이동거리, 현 위치
    distance[start] = 0
    while q:
        dist, now = heapq.heappop(q)
        if distance[now] < dist: # 처리한 적 있는 노드라면 무시
            continue
        for i in L[now]:
            cost = dist + i[1] # 시작지점에서 부터 목표한 노드까지의 거리
            if cost < distance[i[0]]: # 그게 현재의 최소값보다 작다면 변경해줌
                distance[i[0]] = cost
                heapq.heappush(q, (cost, i[0]))

dijkstra(start)

for i in range(1, n+1):
    if distance[i] == INF: # 결과에 변동이 없을 때
        print("INFINITY")
    else:
        print(distance[i])

###############################################################################################################
# 플로이드 워셜 행렬을 통해 모든 경우의 수를 더해줌 시간 복잡도 O(N^3)
n, m = map(int, input().split())

graph = [[INF] * (n+1) for _ in range(n+1)]
for a in range(1,n+1):
    for b in range(1, n+1):
        if a==b:
            graph[a][b] = 0

for i in range(m):
    a, b, c = map(int, input().split())
    graph[a][b] = c

for a in range(1, n+1):
    for b in range(1, n+1):
        for c in range(1, n+1):
            graph[a][b] = min(graph[a][b], graph[a][c] + graph[c][b])

for i in range(1, n+1):
    for j in range(1, n+1):
        if graph[i][j] == INF:
            print("INF", end=" ")
        else:
            print(graph[i][j], end= " ")
    print()

'''
6 11
1
1 2 2
1 3 5
1 4 1
2 3 3
2 4 2
3 2 3
3 6 5
4 3 3
4 5 1
5 3 1
5 6 2

4 7
1 2 4
1 4 6
2 1 3
2 3 7
3 1 5
3 4 4
4 3 2
'''