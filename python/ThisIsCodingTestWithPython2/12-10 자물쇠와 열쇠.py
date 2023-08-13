def rotate(L, d):
    n = len(L)
    result = [[0] * n for _ in range(n)]
    if d%4 == 1:
        for i in range(n):
            for j in range(n):
                result[j][n-i-1] = L[i][j]
    elif d%4 == 2:
        for i in range(n):
            for j in range(n):
                result[n-i-1][n-j-1] = L[i][j]
    elif d%4 == 3:
        for i in range(n):
            for j in range(n):
                result[n-j-1][i] = L[i][j]
    else:
        return L
    return result

def check(L):
    n = len(L)//3 # 세배 늘린 자물쇠이므로 중간에 있는 값만 조사할 수 있도록 해야함
    for i in range(n, n*2):
        for j in range(n, n*2):
            if L[i][j] != 1:
                return False
    return True

def solution(key, lock):
    n = len(lock)
    m = len(key)
    new_lock = [[0]*(3*n) for _ in range(3*n)]
    for i in range(n): # 3배로 늘린 열쇠의 중간에 기존 값 넣기
        for j in range(n):
            new_lock[n+i][n+j] = lock[i][j]
    for i in range(1, n*2):
        for j in range(1, n*2):
            for k in range(4):
                key_array = rotate(key, k)
                for x in range(m):
                    for y in range(m):
                        new_lock[i+x][j+y] += key_array[x][y]

                if check(new_lock):
                    return True
                else:
                    for x in range(m):
                        for y in range(m):
                            new_lock[i + x][j + y] -= key_array[x][y]
    return False

rs = solution([[0, 0, 0], [1, 0, 0], [0, 1, 1]], [[1, 1, 1], [1, 1, 0], [1, 0, 1]])
print(rs)