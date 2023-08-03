import sys
input = sys.stdin.readline

# N, M = map(int, input().split())
# L = []
# for _ in range(N):
#     L.append(int(input()))
# d = [10001] * (M+1)
# for i in range(M+1):
#     for l in L:
#         if i % l == 0:
#             d[i] = min(d[i], i//l)
#         if i-l in L:
#             d[i] = min(d[i], d[i-l]+1)
# print(d[M])

N, M = map(int, input().split())
L = []
for _ in range(N):
    L.append(int(input()))
d = [10001] * (M+1)

d[0]=0 # 초기값
for i in L: # 화폐의 액수 기준
    for j in range(i, M+1): # 정수 기준(화폐를 기준으로 시작)
        if d[j - i] != 10001: # 현재의 정수값에서 화폐만큼 뺏을 때 그 값이 할당한 적 있는 값이면 그 값에서 +1(화폐 1개만큼 더해줌)
            d[j] = min(d[j], d[j-i]+1)
print(d[M])
'''
3 4
3
5
7

3 7
2
3
5
'''