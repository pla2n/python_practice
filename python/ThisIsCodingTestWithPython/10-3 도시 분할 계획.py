import sys
input = sys.stdin.readline

n, m = map(int, input().split())
L = []
for i in range(m):
    a, b, c = map(int, input().split())
    L.append((c, a, b))
L.sort()

def find_parent(parent, x):
    if parent[x] != x:
        return find_parent(parent, parent[x])
    return x
def union_parent(parent, a, b):
    a = find_parent(parent, a)
    b = find_parent(parent, b)
    if b > a:
        parent[b] = a
    else:
        parent[a] = b

parent = [0]*(n+1)
for i in range(n+1):
    parent[i] = i

result = 0
for i in range(m):
    if find_parent(parent, L[i][1]) != find_parent(parent, L[i][2]): # 싸이클에 포함되지 않는 경우만 사용
        union_parent(parent, L[i][1], L[i][2])
        result += L[i][0]
        last = L[i][0]
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