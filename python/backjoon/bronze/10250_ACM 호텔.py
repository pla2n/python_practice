import sys
input = sys.stdin.readline

N = int(input())
for k in range(N):
    h, w, n = map(int, input().split())
    L = [[]*(w+1) for i in range(h+1)]
    print(L)
    for i in range(1, h+1):
        for j in range(1, w+1):
            if j > 9:
                L[i][j].append(i)
                L[i][j].append(j)
            else:
                L[i][j].append(i)
                L[i][j].append(0)
                L[i][j].append(j)
    print(L)