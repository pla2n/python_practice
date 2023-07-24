import sys
import copy

N = int(input())
data = []
count = 0
for i in range(N):
    data.append(sys.stdin.readline().strip())

C = [int(x) for x in data if int(x) > 0]
C.sort()
if len(C) % 2 != 0:
    count += C.pop(0)
if len(C) > 1:
    for i in range(0, len(C), 2):
        if C[i] + C[i+1] < C[i] * C[i+1]:
            count += C[i] * C[i+1]
        else:
            count += C[i] + C[i+1]

D = [int(x) for x in data if int(x) <= 0]
D.sort()
A = D.copy()
if len(A) > 1:
    for i in range(0, len(A), 2):
        if i+1 < len(A) and A[i] * A[i+1] > 0:
            count += A[i] * A[i+1]
            D.remove(A[i])
            D.remove(A[i+1])
        else:
            break
while (0 in D):
    if len(D) == 1:
        break
    D.remove(D[0])
    D.remove(D[-1])
    
count += sum(D)
    
print(count)
