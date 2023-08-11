import sys
input = sys.stdin.readline

n = int(input())
L = list(map(int, input().split()))
L.sort()

target = 1

for l in L:
    if target < l: # 최소값 찾는 조건
        break
    target += l
print(target)

'''
5
3 2 1 1 9
'''