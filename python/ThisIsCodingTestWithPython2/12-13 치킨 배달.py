import sys
import itertools
input = sys.stdin.readline

# n, m = map(int, input().split())
# L = [list(map(int, input().split())) for _ in range(n)]
# L1 = []
# L2 = []
# for i in range(n):
#     for j in range(n):
#         if L[i][j] == 1:
#             L1.append((i, j))
#         elif L[i][j] == 2:
#             L2.append((i, j))
#
# def distance(array):
#     result = 0
#     for i in range(len(L1)):
#         stack = 51 # n의 최대값이 50
#         for j in range(len(array)):
#             stack = min(stack, abs(int(L1[i][0])-int(array[j][0])) + abs(int(L1[i][1])-int(array[j][1])))
#         result += stack
#     return result
#
# def chicken():
#     rs = float("inf")
#     for array in itertools.combinations(L2, m):
#         dist = distance(array)
#         rs = min(rs, dist)
#     return rs

def dist(L1, L2):
    result = 0
    for x, y in L1:
        M = float("inf")
        for a, b in L2:
            M = min(M, (abs(a-x) + abs(b-y)))
        result += M
    return result
def chicken():
    n, m = map(int, input().split())
    L = [list(map(int, input().split())) for _ in range(n)]
    L1 = []
    L2 = []
    for i in range(n):
        for j in range(n):
            if L[i][j] == 1:
                L1.append((i, j))
            elif L[i][j] == 2:
                L2.append((i, j))
    M = float("inf")
    for c in itertools.combinations(L2, m):
        M = min(M, dist(L1, c))
    return M
rs = chicken()
print(rs)
