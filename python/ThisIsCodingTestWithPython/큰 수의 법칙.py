import sys
input = sys.stdin.readline

N, M, K = map(int, input().split())
L = list(map(int, input().split()))
L.sort()
k = 0
result = 0
for i in range(M):
    k += 1
    if k < K:
        result += L[-1]
    else:
        result += L[-2]
        k = 0
print(result)

print('-----------------------------------------')

N, M, K = map(int, input().split())
L = list(map(int, input().split()))
L.sort()
result = 0

count = int(M / (K+1)) * K + M % (K+1) # 반복되는 리스트의 크기를 파악하고, 그만큼 K의 반복 횟수를 파악
result += count * L[-1]
result += (M - count) * L[-2]

print(result)

'''
5 8 3
2 4 5 4 6
'''