import sys
input = sys.stdin.readline

N = int(input())
L = [0 for _ in range(N+1)]
t = []
p = []
for i in range(N):
    T, P = map(int, input().strip().split())
    t.append(T)
    p.append(P)
for i in range(N-1, -1, -1):
    if t[i] + i > N: # i가 현재 날짜
        L[i] = L[i+1]
    else:
        L[i] = max(L[i+1], L[t[i] + i] + p[i])
print(L[0])
