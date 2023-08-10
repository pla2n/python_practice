import sys
input = sys.stdin.readline

def find_parent(parent, x):
    if parent[x] != x:
        parent[x] = find_parent(parent, parent[x])
    return parent[x]
def union_parnet(parent, a, b):
    a = find_parent(parent, a)
    b = find_parent(parent, b)
    if b > a:
        parent[b] = a
    else:
        parent[a] = b

n, m = map(int, input().split())
parent = [0] * (n+1)
L = []
for i in range(m):
    a, b, c = map(int, input().split())
    L.append((c, a, b))
for i in range(1, n+1):
    parent[i] = i

L.sort()
result = 0
last = 0
for l in L:
    cost, a, b = l
    if find_parent(parent, a) != find_parent(parent, b):
        union_parnet(parent, a, b)
        result += cost
        last = cost
print(result - last)

'''
7 12
1 2 3
1 3 2
3 2 1
2 5 2
3 4 4
7 3 6
5 1 5
1 6 2
6 4 1
6 5 3
4 5 3
6 7 4
'''