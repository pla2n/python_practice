def solution(s):
    answer = 0
    result = []
    if len(s) == 1:
        return 1
    for i in range(1, len(s)+1):
        b = ''
        tmp = s[:i]
        cnt = 1
        for j in range(i, len(s) + i, i):
            if tmp == s[j:i+j]:
                cnt += 1
            else:
                if cnt != 1:
                    b = b + str(cnt) + tmp
                else:
                    b = b + tmp
                tmp = s[j:i+j]
                cnt = 1
        result.append(len(b))
    return min(result)

result = solution('aabbaccc')
print(result)