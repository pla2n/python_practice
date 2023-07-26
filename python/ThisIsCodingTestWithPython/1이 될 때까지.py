import sys

N, K = map(int, sys.stdin.readline().split())
count = 0
while N != 1:
    if N % K == 0:
        N /= K
        count += 1
    else:
        N -= 1
        count += 1
print(count)

N, K = map(int, sys.stdin.readline().split())
result = 0
while True:
    target = (N // K) * K # for 반복문 대신, 직접 반복횟수를 계산해줌으로써 시간 복잡도를 줄임
    result += N-target
    N = target
    if N < K:
        break
    N //= K
    result += 1
result += (N-1)
print(result)