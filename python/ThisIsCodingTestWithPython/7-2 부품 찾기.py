import sys
input = sys.stdin.readline

N = int(input())
A = list(map(int, input().split()))
M = int(input())
B = list(map(int, input().split()))

for i in range(M): # 집합 자료형 풀이
    if B[i] in A:
        print("yes", end=' ')
    else:
        print("no", end=' ')
print('')
def binary_search(array, target, start, end):
    if start > end:
        return None
    mid = (start + end) // 2
    if array[mid] == target:
        return mid+1
    elif array[mid] > target:
        return binary_search(array, target, 0, mid-1)
    else:
        return binary_search(array, target, mid+1, end)

A.sort()
for i in range(M):
    if binary_search(A, B[i], 0, N) == None:
        print("no", end=' ')
    else:
        print("yes", end=' ')
'''
5
8 3 7 9 2
3
5 7 9
'''