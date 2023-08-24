# import sys
# input = sys.stdin.readline
# d = [0] * 41
# counter = [[0, 0] for _ in range(41)]
# def fibonacci(n):
#     if (n == 0):
#         print(counter[n][0])
#         counter[n][0] += 1
#         return 0
#     elif (n == 1):
#         counter[n][1] += 1
#         return 1
#     else:
#         d[n] = fibonacci(n - 1) + fibonacci(n - 2)
#         return d[n]
#
# n = int(input())
# result = []
# for i in range(n):
#     a = int(input())
#     counter = [0, 0]
#     fibonacci(a)
#     result.append(counter[n])
# for a, b in result:
#     print(a, b)


T = int(input())
for _ in range(T):
    N = int(input())
    zero,one=1,0 # zero: 0개수, one: 1개수
    for i in range(N):
        zero,one = one,zero+one # zero와 one에 대해 피보나치적용
    print(zero,one)