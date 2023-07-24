#import sys

#def reverse(x, y):
#    for i in range(x, x+3):
#        for j in range(y, y+3):
#            L1[i][j] = 1 - L1[i][j]
#def check():
#    for i in range(N):
#        for j in range(M):
#            if L1[i][j] != L2[i][j]:
#                return False
#    return True
#N, M = map(int, sys.stdin.readline().split())
#L1 = []
#L2 = []
#count = 0
#for i in range(2):
#    for j in range(N):
#        if i == 1:
#            L1.append(list(map(int, sys.stdin.readline().strip())))
#        else:
#            L2.append(list(map(int, sys.stdin.readline().strip())))
#for i in range(N-2):
#    for j in range(M-2):
#        if L1[i][j] != L2[i][j]:
#            reverse(i,j)
#            count += 1
#if check():
#    print(count)
#else:
#    print("-1")

import sys
input = sys.stdin.readline

def reverse(x, y):
    for i in range(x, x+3):
        for j in range(y, y+3):
            L[i][j] = 1 - L[i][j]

def check():
    for i in range(N):
        for j in range(M):
            if L[i][j] != rL[i][j]:
                return False
    return True

N, M = map(int, input().split())

L = [list(map(int, input().strip())) for _ in range(N)]
rL = [list(map(int, input().strip())) for _ in range(N)]
count = 0

for i in range(N-2):
    for j in range(M-2):
        if L[i][j] != rL[i][j]:
            reverse(i, j)
            count += 1

if check():
    print(count)
else:
    print("-1")