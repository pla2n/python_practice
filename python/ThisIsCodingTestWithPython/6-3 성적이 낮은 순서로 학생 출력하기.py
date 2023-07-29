import sys
input = sys.stdin.readline

N = int(input())
L = [input().split() for _ in range(N)]
L.sort(key=lambda x:x[1])

for i, j in L:
    print(i, end=' ')

'''
2
홍길동 95
이순신 77
 '''