import sys
input = sys.stdin.readline

N, K = map(int, input().split())
L = [list(map(int, input().split())) for _ in range(2)]
L[0].sort()
L[1].sort(reverse=True)
for k in range(K):
    if L[0][k] < L[1][k]:
        L[0][k], L[1][k] = L[1][k], L[0][k]
    else:
        break
print(sum(L[0]))

'''
5 3
1 2 5 4 3
5 5 6 6 5
'''