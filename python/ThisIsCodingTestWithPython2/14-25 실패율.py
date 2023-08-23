from collections import Counter
def solution(N, stages):
    answer = []
    c = Counter(stages)
    stack = len(stages)
    for i in range(1, N+1):
        if stack != 0:
            answer.append((c[i]/stack, i))
        else:
            answer.append((0, i))
        stack -= c[i]
    answer.sort(reverse=True, key=lambda x:(x[0], -x[1]))
    return [a[1] for a in answer]

rs = solution(2, [1, 1, 1, 1])
print(rs)