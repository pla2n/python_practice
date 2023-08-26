import sys
input = sys.stdin.readline
T = int(input())

for a in range(T):
    n, m = map(int, input().split())
    L = [[0] for _ in range(n)]
    A = list(map(int, input().split()))
    for b in range(n):
        L[b] = A[b*m:b*m+m]
    for j in range(1, m):
        L[0][j] = max(L[0][j] + L[0][j - 1], L[0][j] + L[1][j - 1])
        for i in range(1, n-1):
            L[i][j] = max(L[i][j]+L[i-1][j-1], L[i][j]+L[i][j-1], L[i][j]+L[i+1][j-1])
        L[n-1][j] = max(L[n-1][j] + L[n-1][j - 1], L[n-1][j] + L[n-2][j - 1])
    max_value = [x[m-1] for x in L]
    print(max(max_value))


'''
2
3 4
1 3 3 2 2 1 4 1 0 6 4 7
4 4
1 3 1 5 2 2 4 1 5 0 2 3 0 6 1 2
'''