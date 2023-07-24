def solution(data):
    sand = '12341'
    count = 0
    s= ''.join(map(str, data))
    while s.find(sand) !=  -1:
        s = s.replace(sand, '', 1)
        count += 1
    return count

A = solution([1, 1, 1, 2, 3, 4, 1, 2, 3, 4, 1])
print(A)

def solution(data):
    sand = '12341'
    count = 0
    s = ''.join(map(str, data))

    while s.find(sand) != -1:
        s = s.replace(sand, '', 1)
        count += 1
    return count

A = solution([1, 1, 1, 2, 3, 4, 1, 2, 3, 4, 1])
print(A)
