def valid(result):
    for x, y, a in result:
        if a == 0:  # 기둥 설치
            if y == 0 or [x,y-1,a] in result or [x-1, y, 1] in result or [x, y, 1] in result:
                continue
            return False
        else:  # 보 설치
            if [x, y-1, 0] in result or [x+1, y-1, 0] in result or ([x-1, y, 1] in result and [x+1, y, 1] in result):
                continue
            return False
    return True

def solution(n, build_frame):
    result = []
    for build in build_frame:
        x, y, a, b = build
        if b == 1:
            result.append([x, y, a])
            if not valid(result):
                result.remove([x, y, a])
        else:
            result.remove([x, y, a])
            if not valid(result):
                result.append([x, y, a])
    return sorted(result)
# rs = solution(5, [[1, 0, 0, 1], [1, 1, 1, 1], [2, 1, 0, 1], [2, 2, 1, 1], [5, 0, 0, 1], [5, 1, 0, 1], [4, 2, 1, 1], [3, 2, 1, 1]])
# print(rs)
rs = solution(5, [[0, 0, 0, 1], [2, 0, 0, 1], [4, 0, 0, 1], [0, 1, 1, 1], [1, 1, 1, 1], [2, 1, 1, 1], [3, 1, 1, 1], [2, 0, 0, 0], [1, 1, 1, 0], [2, 2, 0, 1]])
print(rs)

