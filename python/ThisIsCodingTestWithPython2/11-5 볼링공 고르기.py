import sys
input = sys.stdin.readline

n, m = map(int, input().split())
K = list(map(int, input().split()))

result = 0
for i in range(n-1):
    for j in range(i, n):
        if K[i] != K[j]:
            result += 1
print(result)

'''
5 3
1 3 2 3 2

8 5
1 5 4 3 2 4 5 2
'''

n, m = map(int, input().split())
L = list(map(int, input().split()))
count = 0
for i in range(n-1):
    for j in range(i, n):
        if L[i] != L[j]:
            count += 1
print(count)