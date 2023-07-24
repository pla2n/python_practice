def solution(data):
    def check(x, y):
        if x < 0 or y < 0 or x > N or y > M:
            return False
        if data[x][y] == '#':
            return False
        return True
    N = len(data)-1
    M = len(data[0])-1
    queue = []
    queue.append([0,0])
    fish = data[0][0]
    data[0][0] = 0
    visited = set()
    count = 0
    goal = False
    while queue:
        count += 1
        if count == (N*M)**3:
            if goal:
                return fish
            return -1
        x, y = queue.pop(0)
        visited.add((x,y))
        if x == N and y == M:
            fish += data[x][y]
            data[x][y] = 0
            goal = True

        if check(x, y-1):
            queue.append([x, y-1])
            fish += data[x][y-1]
            data[x][y-1] = 0
        if check(x, y+1):
            queue.append([x, y+1])
            fish += data[x][y+1]
            data[x][y+1] = 0
        if check(x-1, y):
            queue.append([x-1, y])
            fish += data[x-1][y]
            data[x-1][y] = 0
        if check(x+1, y):
            queue.append([x+1, y])
            fish += data[x+1][y]
            data[x+1][y] = 0
    return None

A = solution([[1, 3, '#'], [0, '#', 2], [0, 1, 1]])
print(A)

def solution(data):
    def check(x, y):
        if x > N or x < 0 or y > N or y < 0:
            return False
        if data[x][y] == '#':
            return False
        return True
    N = len(data)-1
    M = len(data[0])-1
    count = 0
    queue = []
    visited = set()
    queue.append([0,0])
    fish = data[0][0]
    data[0][0] = 0
    goal = False
    while queue:
        count += 1
        if count == (N*M) ** 3:
            if goal:
                return fish
            return -1
        x, y = queue.pop(0)
        visited.add((x,y))
        if x == N and y == M:
            goal = True
            fish += data[x][y]
            data[x][y] = 0
        if check(x, y-1):
            fish += data[x][y-1]
            data[x][y-1] = 0
            queue.append([x, y-1])
        if check(x, y+1):
            fish += data[x][y+1]
            data[x][y+1] = 0
            queue.append([x, y+1])
        if check(x-1, y):
            fish += data[x-1][y]
            data[x-1][y] = 0
            queue.append([x-1, y])
        if check(x+1, y):
            fish += data[x+1][y]
            data[x+1][y] = 0
            queue.append([x+1, y])
    return None
A = solution([[1, 3, '#'], [0, '#', 2], [0, 1, 1]])
print(A)
    
