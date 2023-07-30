import sys
input = sys.stdin.readline

N, M = map(int, input().split())
L = list(map(int, input().split()))
count = min(L)
while True:
    result = 0
    for x in L:
        result += x-count
    if result >= M:
        break
    count += 1
print(count)

'''
4 6
19 15 10 17
4 7
20 15 10 17
5 20
4 42 40 26 46
'''