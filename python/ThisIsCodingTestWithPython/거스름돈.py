import sys
input = sys.stdin.readline

N = int(input())

count = [500, 100, 50, 10]
result = 0
for i in count:
    n = int(N / i)
    result += n
    N %= i
print(result)