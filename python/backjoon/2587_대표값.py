import sys
input = sys.stdin.readline

L = [int(input()) for _ in range(5)]
L.sort()
print(int(sum(L)/5))
print(L[2])
