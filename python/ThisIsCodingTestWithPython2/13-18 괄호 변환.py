def fin(P):
    count = 0
    for i in range(len(P)):
        if P[i] == '(':
            count += 1
        else:
            count -= 1
        if count == 0:
            return i
def check(P):
    left = 0
    right = 0
    result = ""
    for p in P:
        if left < right:
            return False
        if p == '(':
            left += 1
        elif p == ')':
            right += 1
    return left == right

def solution(P):
    result = ""
    if P == '':
        return result
    index = fin(P)
    u = P[:index+1]
    v = P[index+1:]
    if check(u):
        result += u + solution(v)
    else:
        result = '('
        result += solution(v)
        result += ')'
        u = list(u[1:-1])
        for i in range(len(u)):
            if u[i] == '(':
                u[i] = ')'
            elif u[i] == ')':
                u[i] = '('
        result += "".join(u)
    return result

print(solution("()))((()"))