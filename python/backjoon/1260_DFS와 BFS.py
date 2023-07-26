#import sys
#from collections import deque
#input = sys.stdin.readline

#n, m, v = map(int, input().split())
#additionall = []
#l = [list(map(int, input().split())) for _ in range(m)]
#for i in range(m):
#    additionall.append([l[i][1], l[i][0]])
#l.extend(additionall)
#l.sort(key=lambda x:(x[0], x[1]))

#def dfs(x):
#    if len(result) == n:
#        return result
#    else:
#        result.append(x)
#        for i in range(2*m):
#            if l[i][0] == x and l[i][1] not in result:
#                dfs(l[i][1])

#def bfs(x):
#    q = deque()
#    q.append((x))
#    result.append(x)
#    while q and len(result) < n:
#        k = q.popleft()
#        for i in range(2*m):
#            if l[i][0] == k and l[i][1] not in result:
#                result.append(l[i][1])
#                q.append(l[i][1])
#    return result
#for i in range(2):
#    result = []
#    if i == 0:
#        dfs(v)
#    else:
#        bfs(v)
#    for i in result:
#        print(i, end=' ')
#    print()



# https://ji-gwang.tistory.com/291
from collections import deque

N, M, V = map(int, input().split())

graph = [[False] * (N + 1) for _ in range(N + 1)]

for _ in range(M):
    a, b = map(int, input().split())
    graph[a][b] = True
    graph[b][a] = True

visited1 = [False] * (N + 1)  # dfs의 방문기록
visited2 = [False] * (N + 1)  # bfs의 방문기록
print(graph)
print(visited1)
print(visited2)

def bfs(V):
    q = deque([V])  # pop메서드의 시간복잡도가 낮은 덱 내장 메서드를 이용한다
    visited2[V] = True  # 해당 V 값을 방문처리
    while q:  # q가 빌때까지 돈다.
        V = q.popleft()  # 큐에 있는 첫번째 값 꺼낸다.
        print(V, end=" ")  # 해당 값 출력
        for i in range(1, N + 1):  # 1부터 N까지 돈다
            if not visited2[i] and graph[V][i]:  # 만약 해당 i값을 방문하지 않았고 V와 연결이 되어 있다면
                q.append(i)  # 그 i 값을 추가
                visited2[i] = True  # i 값을 방문처리


def dfs(V):
    visited1[V] = True  # 해당 V값 방문처리
    print(V, end=" ")
    for i in range(1, N + 1):
        if not visited1[i] and graph[V][i]:  # 만약 i값을 방문하지 않았고 V와 연결이 되어 있다면
            dfs(i)  # 해당 i 값으로 dfs를 돈다.(더 깊이 탐색)


dfs(V)
print()
bfs(V)