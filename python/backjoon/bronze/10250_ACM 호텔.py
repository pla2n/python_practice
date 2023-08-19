import sys
input = sys.stdin.readline

N = int(input())
for k in range(N):
    h, w, n = map(int, input().split())
    L = [[0]*(w+1) for i in range(h+1)]
    for i in range(1, h+1):
        for j in range(1, w+1):
            L[i][j] += 100*i + j
    count = 0
    for i in range(1, w+1):
        for j in range(1, h+1):
            count += 1
            if count == n:
                print(L[j][i])


for _ in range(int(input())):
    H,W,N=map(int,input().split())
    if N%H:
        print((N%H)*100+N//H+1)
    else:
        print(H*100+N//H)