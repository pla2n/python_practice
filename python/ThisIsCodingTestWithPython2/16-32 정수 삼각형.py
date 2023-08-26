import sys
input = sys.stdin.readline

n = int(input())
L = [list(map(int, input().split())) for _ in range(n)]

for i in range(1, n):
    for j in range(i+1):
        if j >= i:
            max_value = L[i - 1][j - 1]
        elif j == 0:
            max_value = L[i-1][j]
        else:
            max_value = max(L[i - 1][j - 1], L[i - 1][j])
        L[i][j] += max_value
print(max(L[-1]))

'''
5
7
3 8
8 1 0
2 7 4 4
4 5 2 6 5
'''