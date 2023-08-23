import itertools
import sys
import copy
from collections import deque
input = sys.stdin.readline

# n = int(input())
# L = list(map(int, input().split()))
# array = list(map(int, input().split()))
#
# def bfs(aL, L):
#     q = []
#     count = 0
#     q = deque(aL)
#     while q:
#         a = q.popleft()
#         if a == 0:
#             L[count+1] += L[count]
#         elif a == 1:
#             L[count+1] = L[count] - L[count+1]
#         elif a == 2:
#             L[count+1] *= L[count]
#         elif a == 3:
#             L[count+1] = int(L[count] / L[count+1])
#         count += 1
#     return L[-1]
#
# aL = []
# rs = []
# for i in range(4):
#     for j in range(array[i]):
#         aL.append(i)
# for a in list(itertools.permutations(aL, n-1)):
#     cL = copy.copy(L)
#     rs.append(bfs(a, cL))
# print(max(rs))
# print(min(rs))


n = int(input())

data = list(map(int, input().split()))
add, sub, mul, div = map(int, input().split())

minv = int(1e9)
maxv = -int(1e9)
def dfs(i, now, add, sub, mul, div):
    global minv, maxv
    if i == n:
        minv = min(minv, now)
        maxv = max(maxv, now)
    else:
        if add > 0:
            add -= 1
            dfs(i+1, now+data[i], add, sub, mul, div)
            add += 1
        if sub > 0:
            sub -= 1
            dfs(i+1, now-data[i], add, sub, mul, div)
            sub += 1
        if mul > 0:
            mul -= 1
            dfs(i+1, now*data[i], add, sub, mul, div)
            mul += 1
        if div > 0:
            div -= 1
            dfs(i+1, int(now/data[i]), add, sub, mul, div)
            div += 1
dfs(1, data[0], add, sub, mul, div)

print(maxv)
print(minv)