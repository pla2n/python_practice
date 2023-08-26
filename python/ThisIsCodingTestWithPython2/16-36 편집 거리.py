A = input()
B = input()
AL = len(A)
BL = len(B)

dp = [[0]*(BL+1) for _ in range(AL+1)]

for i in range(1, AL+1): # 제일 왼쪽 변과 위쪽 변은 참고하기 위한 거리를 만들어 줌(수정 횟수)
    dp[i][0] = i
for j in range(1, BL+1):
    dp[0][j] = j

for i in range(1, AL+1): # 이 반복문 안에 들어가는 값이 반복 횟수임
    for j in range(1, BL+1):
        if A[i-1] == B[j-1]: # 문자가 같다면 수정이 필요하지 않음
            dp[i][j] = dp[i-1][j-1]
        else:
            dp[i][j] = 1 + min(dp[i][j-1], dp[i-1][j], dp[i-1][j-1]) # 왼쪽, 왼쪽 위, 위 중 가장 작은 값에 수정값 +1
print(dp[AL][BL])