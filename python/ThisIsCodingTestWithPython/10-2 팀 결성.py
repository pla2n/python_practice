import sys
input = sys.stdin.readline

n, m = map(int, input().split())
L = []
parent = [0] * (n+1)
for _ in range(m):
    L.append(list(map(int, input().split())))
def find_parent(parent, x):
    if parent[x] != x:
        return find_parent(parent, parent[x])
    return x

def union_parent(parent, a, b):
    a = find_parent(parent, a)
    b = find_parent(parent, b)
    if a < b:
        parent[b] = a
    else:
        parent[a] = b

for _ in range(n+1):
    parent[_] = _

for i in range(m):
    if L[i][0] == 0:
        union_parent(parent, L[i][1], L[i][2])
    else:
        if find_parent(parent, L[i][1]) == find_parent(parent, L[i][2]):
            print("Yes")
        else:
            print("No")
'''
7 8
0 1 3
1 1 7
0 7 6
1 7 1
0 3 7
0 4 2
0 1 1
1 1 1
'''