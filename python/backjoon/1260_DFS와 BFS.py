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

visited1 = [False] * (N + 1)  # dfs�� �湮���
visited2 = [False] * (N + 1)  # bfs�� �湮���
print(graph)
print(visited1)
print(visited2)

def bfs(V):
    q = deque([V])  # pop�޼����� �ð����⵵�� ���� �� ���� �޼��带 �̿��Ѵ�
    visited2[V] = True  # �ش� V ���� �湮ó��
    while q:  # q�� �������� ����.
        V = q.popleft()  # ť�� �ִ� ù��° �� ������.
        print(V, end=" ")  # �ش� �� ���
        for i in range(1, N + 1):  # 1���� N���� ����
            if not visited2[i] and graph[V][i]:  # ���� �ش� i���� �湮���� �ʾҰ� V�� ������ �Ǿ� �ִٸ�
                q.append(i)  # �� i ���� �߰�
                visited2[i] = True  # i ���� �湮ó��


def dfs(V):
    visited1[V] = True  # �ش� V�� �湮ó��
    print(V, end=" ")
    for i in range(1, N + 1):
        if not visited1[i] and graph[V][i]:  # ���� i���� �湮���� �ʾҰ� V�� ������ �Ǿ� �ִٸ�
            dfs(i)  # �ش� i ������ dfs�� ����.(�� ���� Ž��)


dfs(V)
print()
bfs(V)