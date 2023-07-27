# 시간당 경우의 수는 3600개
N = int(input())
result = 0
for i in range(N+1):
    for j in range(60):
        for k in range(60):
            if '3' in str(i) + str(j) + str(k):
                result += 1
print(result)