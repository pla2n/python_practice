import sys
input = sys.stdin.readline

n = int(input())
L = list(map(int, input().split()))
L.sort()
count = 0
rs = 0
for i in range(n):
    count += 1
    if count >= L[i]:
        rs += 1
        count = 0
print(rs)

'''
5
2 3 1 2 2
'''

n = int(input())
L = list(map(int, input().split()))
L.sort()
count = 0
rs = 0
for i in range(n):
    count += 1
    if count == L[i]:
        count = 0
        rs += 1
print(rs)
