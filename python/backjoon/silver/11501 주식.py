import sys
input = sys.stdin.readline

for t in range(int(input())):
    n = int(input())
    L = list(map(int, input().split()))
    max_value = 0
    profit = 0
    L.reverse()
    for i in range(n):
        if L[i] >= max_value:
            max_value = L[i] # max_value를 큰 값이 나올때마다 갱신하여 구간의 최대값에 따른 이자를 구할 수 있음
            continue
        profit += max_value - L[i]

    print(profit)