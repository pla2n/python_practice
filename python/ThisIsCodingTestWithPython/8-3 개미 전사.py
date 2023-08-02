import sys
input = sys.stdin.readline

d = [0] * 100
N = int(input())
K = list(map(int, input().split()))
d[0] = K[0]
d[1] = max(K[0], K[1])
for i in range(2, N):
    d[i] = max(d[i-1], d[i-2] + K[i]) # 항상 최대가 될 수 있는 값으로 더해줌
print(d[N-1])

'''
4
1 3 1 5
'''