import sys
input = sys.stdin.readline

N = int(input().strip())
A = list(map(int, input().strip().split()))
B, C = map(int, input().split())

count = 0
result = 0

for i in range(N):
    A[i] -= B
    result += 1
    if A[i] > 0:
        if A[i] % C == 0:
            result += A[i] / C
        else:
            result += int(A[i] / C) + 1
print(int(result))
