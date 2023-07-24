def solution(data):
    L = {}
    for i in range(len(data[0])):
        if data[0][i] in L:
            L[data[0][i]] += data[1][i]
        else:
            L[data[0][i]] = data[1][i]
    L = sorted(L.items(), key=lambda x: x[1], reverse=True)
    return [item[0] for item in L]

A = solution([["스핑크스", "브리티시숏헤어", "스핑크스", "스핑크스", "벵갈", "메인쿤"], [3, 16, 1, 9, 25, 5]])
print(A)
