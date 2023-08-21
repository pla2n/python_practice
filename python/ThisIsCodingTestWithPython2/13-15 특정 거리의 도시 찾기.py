#backjoon 18352
# import sys
# from collections import deque
# input = sys.stdin.readline
#
# n, m, k, x = map(int, input().split())
# L = [list(map(int, input().split())) for _ in range(m)]
# result = []
# def bfs(x):
#     q = deque([x])
#     count = 1
#     while q:
#         a = q.popleft()
#         if count == k:
#             return a
#         for l in L:
#             if l[0] == a:
#                 q.append([l[1]])
#                 count += 1
#     return count
# for l in L:
#     if l[0] == x:
#         rs = bfs(l[1])
#         result.append(rs)
# result.sort(reverse=True)
# for i in result:
#     print(i)


import sys
from collections import deque

input = sys.stdin.readline

n, m, k, x = map(int, input().split())
L = [list(map(int, input().split())) for _ in range(m)]

# graph = [[] for _ in range(n+1)]
#
# visited = [False] * (n+1)
# for l in L:
#     graph[l[0]].append(l[1])
#
# def bfs(x, visited):
#     dist = [float("inf")] * (n+1)
#     dist[x] = 0
#     q = deque([x])
#     while q:
#         node = q.popleft()
#         for i in graph[node]:
#             if not visited[i]:
#                 dist[i] = min(dist[i], dist[node]+1)
#                 q.append(i)
#                 visited[i] = True
#     return [node for node in range(1, n+1) if dist[node] == k]
# result = bfs(x, visited)
# if result:
#     result.sort()
#     for city in result:
#         print(city)
# else:
#     print(-1)

def bfs():
    dist = [float("inf")] * (n+1)
    dist[x] = 0
    q = deque([x])
    while q:
        node = q.popleft()
        for i in graph[node]:
            if dist[i] == float("inf"):
                dist[i] = min(dist[i], dist[node] + 1)
                q.append(i)
    return [i for i in range(1, n+1) if dist[i] == k]

graph = [[] for _ in range(n+1)]
for l in L:
    graph[l[0]].append(l[1])

rs = bfs()
if rs:
    for i in rs:
        print(i)
else:
    print(-1)