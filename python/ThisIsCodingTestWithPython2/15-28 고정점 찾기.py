import sys
input = sys.stdin.readline

n = int(input())
L = list(map(int, input().split()))

def binary(array, target, start, end):
    while start <= end:
        mid = (start+end) // 2
        if array[mid] == target:
            return mid
        elif array[mid] > target:
            end = mid - 1
        elif array[mid] < target:
            start = mid+1
    return -1

for i in range(n):
    rs = binary(L, i, 0, n)
    if rs == i:
        break
print(rs)
'''
5
-15 -6 1 3 7

7
-15 -4 2 8 9 13 15

7
-15 -4 3 8 9 13 15
'''