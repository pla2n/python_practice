import sys
input = sys.stdin.readline

n, c = map(int, input().split())
L = [int(input()) for _ in range(n)]
L.sort()

def binary(array, start, end):
    while start <= end:
        value = array[0]
        count = 1
        mid = (start+end) // 2 # mid는 최소 거리
        for i in range(1, n):
            if value + mid <= array[i]:
                value = array[i]
                count += 1
        if count >= c: # 더 많은 공유기 설치 가능하다면
            start = mid+1
            result = mid
        else:
            end = mid-1
    return result

rs = binary(L, 1, L[-1]-L[0])
print(rs)