S = list(map(int, input()))
result = S[0]
for i in range(1, len(S)):
    if result * S[i] > result+S[i]:
        result *= S[i]
    else:
        result += S[i]
print(result)

s = list(map(int, input().strip()))
for i in range(1, len(s)):
    if s[i-1] * s[i] > s[i-1]+s[i]:
        s[i] = s[i-1] * s[i]
    else:
        s[i] = s[i - 1] + s[i]
print(s[-1])