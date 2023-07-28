'''
이런 식으로 프로그래밍 해 본적은 없는 것 같아서 참고용으로 작성
'''
def dfs(g, v, visited):
    # 현재 노드를 방문처리
    visited[v] = True
    for i in g[v]:
        if not visited[i]:
            dfs(g, i, visited)

g = [
    [2, 3, 8],
    [1, 7],
    [1, 4 ,5],
    [3, 5],
    [3, 4],
    [7],
    [2, 6, 8],
    [1, 7]
]

visited = [False] * 9
dfs(g, 1, visited)