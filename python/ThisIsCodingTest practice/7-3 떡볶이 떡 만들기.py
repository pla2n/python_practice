import sys
input = sys.stdin.readline

n, m = map(int, input().split())
L = list(map(int, input().split()))

def search(L, start, end):
    global n, m
    if start >= end:
        return None
    mid = (start+end) // 2
    count = 0
    for i in range(n):
        count += max(0, L[i] - mid)
    if count == m:
        return mid
    elif count < m:
        return search(L, 0, mid-1)
    else:
        return search(L, mid+1, end)
rs = search(L, 0, max(L))
if rs == None:
    print("불가")
else:
    print(rs)
'''
4 6
19 15 10 17
'''