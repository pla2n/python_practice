import sys
import itertools
input = sys.stdin.readline

N = int(input())
L = []
I = []
B = []
result = []
for i in range(N):
    L.append(list(map(int, input().strip().split())))
    I.append(i)
A = list(itertools.combinations(I, int(N/2)))
for i in A:
    B.append(list(set(I)-set(i)))
for i in range(len(A)):
    C = list(itertools.combinations(A[i], 2))
    D = list(itertools.combinations(B[i], 2))
    AR = 0
    BR = 0
    for j in range(len(C)):
        AR += L[C[j][0]][C[j][1]] + L[C[j][1]][C[j][0]]
        BR += L[D[j][0]][D[j][1]] + L[D[j][1]][D[j][0]]
    result.append(AR-BR)
result = filter(lambda x:x>-1, result)
print(min(result))
