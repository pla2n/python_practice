import sys
input = sys.stdin.readline

n, c = map(int, input().split())
L = [int(input()) for _ in range(n)]
L.sort()

# def binary(array, start, end):
#     while start <= end:
#         value = array[0] # 첫번쨰 위치
#         count = 1
#         mid = (start+end) // 2 # mid는 최소 거리
#         for i in range(1, n): # 가장 많은 위치가 저장되는 경우의수를 찾아야함
#             if value + mid <= array[i]: # 현재 위치 + 간격 보다 위치가 크다면 저장
#                 value = array[i] # 현재 위치 갱신
#                 count += 1 # 위치의 개수
#         if count >= c: # 더 많은 공유기 설치 가능하다면
#             start = mid+1
#             result = mid
#         else:
#             end = mid-1
#     return result

def binary(array, start, end):
    while start <= end:
        value = array[0]
        count = 1
        mid = (start+end)//2
        print(mid)
        for i in range(1, n):
            if value + mid <= array[i]:
                print(value+mid, array[i])
                value = array[i]
                count += 1
        if count >= c:
            start = mid + 1
            result = mid
        else:
            end = mid - 1
    return result

rs = binary(L, 1, L[-1]-L[0])
print(rs)

'''
5 3
1
2
8
4
9
'''