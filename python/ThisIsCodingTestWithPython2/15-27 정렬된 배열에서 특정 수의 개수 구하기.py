import sys
input = sys.stdin.readline

n, x = map(int, input().split())
L = list(map(int, input().split()))
#
# def binary(array, target, start, end):
#     while start <= end:
#         mid = (start + end) // 2
#         if array[mid] == target:
#             return mid
#         elif array[mid] < target:
#             start = mid+1
#         elif array[mid] > target:
#             end = mid-1
#     return None
#
# rs = 1
# result = 0
# while rs:
#     rs = binary(L, x, 0, n-result)
#     if rs:
#         result += 1
#         L.remove(x)
# print(result)

from bisect import bisect_left, bisect_right

def count_by_range(array, left_value, right_value):
    right_index = bisect_right(array, right_value)
    left_index = bisect_left(array, left_value)
    return right_index-left_index

count = count_by_range(L, x, x)

if count == 0:
    print(-1)
else:
    print(count)

'''
7 2
1 1 2 2 2 2 3
'''