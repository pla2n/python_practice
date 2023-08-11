S = list(map(int, input()))
result = S[0]
for i in range(1, len(S)):
    if result * S[i] > result+S[i]:
        result *= S[i]
    else:
        result += S[i]
print(result)