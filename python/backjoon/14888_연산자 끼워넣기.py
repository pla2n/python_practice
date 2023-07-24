import sys
import itertools
import copy
input = sys.stdin.readline

n = int(input())
A = list(map(int, input().strip().split()))
b = list(map(int, input().strip().split()))
B = []
for i in range(4):
    for j in range(b[i]):
        B.append(i)
B = list(itertools.permutations(B, n-1))

result = []

for i in range(len(B)):
    C = copy.copy(A)
    for j in range(1, n):
        if B[i][j-1] == 0:
            C[j] = C[j-1] + C[j]
        elif B[i][j-1] == 1:
            C[j] = C[j-1] - C[j]
        elif B[i][j-1] == 2:
            C[j] = C[j-1] * C[j]
        elif B[i][j-1] == 3:
            C[j] = int(C[j-1] / C[j])
    result.append(C[-1])
print(max(result))
print(min(result))
