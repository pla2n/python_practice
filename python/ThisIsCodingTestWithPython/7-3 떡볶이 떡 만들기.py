import sys
input = sys.stdin.readline

N, M = map(int, input().split())
L = list(map(int, input().split()))
start = 0
end = max(L)
result = 0
while (start <= end): # while문 이진 탐색 (주어진 N, M의 범위가 너무 크기 떄문에)
    total = 0
    mid = (start + end) // 2
    for l in L:
        if l > mid:
            total += l - mid
    if total < M:
        end = mid - 1
    else:
        result = mid
        start = mid + 1

print(result)

'''
4 6
19 15 10 17
4 7
20 15 10 17
5 20
4 42 40 26 46
'''