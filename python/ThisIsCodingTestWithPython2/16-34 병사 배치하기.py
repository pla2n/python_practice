import sys
input = sys.stdin.readline

n = int(input())
L = list(map(int, input().split()))
L.reverse()
graph = [1]*n
result = []
for i in range(1, n):
    for j in range(0, i):
        if L[j] < L[i]:
            graph[i] = max(graph[i], graph[j]+1)
print(n-max(graph))


'''
7
15 11 4 8 5 2 4
'''