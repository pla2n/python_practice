# 몇 블록으로 나뉘어 있는 지 확인 후, 블록의 수가 작은 것을 출력하면 정답.
# S = list(map(int, input()))
# c0 = 0
# c1 = 0
#
# if S[0] == 0:
#     c0 += 1
# else:
#     c1 += 1
# for i in range(len(S)-1):
#     if S[i] != S[i+1]:
#         if S[i] == 0:
#             c0 += 1
#         else:
#             c1 += 1
# result = min(c0, c1)
# print(result)

L = list(map(int, input()))
c0=0
c1=0
for i in range(1, len(L)):
    if L[i-1] != L[i]:
        if L[i-1] == 0:
            c0 += 1
        else:
            c1 += 1

if L[-1] == 0:
    c0 += 1
else:
    c1 += 1
print(min(c0, c1))