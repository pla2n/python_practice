def solution(data):
    count = 0
    for i in range(len(data)):
        for j in range(len(data[0])):
            if data[i][j] == '#':
                count += 1
                if i > 0: # 2
                    if data[i-1][j] != '#':
                        data[i-1][j] += 1
                    if j > 0: # 1
                        if data[i-1][j-1] != '#':
                            data[i-1][j-1] += 1
                    if j < len(data)-1: # 3
                        if data[i-1][j+1] != '#':
                            data[i-1][j+1] += 1
                if j > 0: # 4
                    if data[i][j-1] != '#':
                        data[i][j-1] += 1
                    if i < len(data)-1: # 7
                        if data[i+1][j-1] != '#':
                            data[i+1][j-1] += 1
                if j < len(data)-1: # 6
                    if data[i][j+1] != '#':
                        data[i][j+1] += 1
                    if i < len(data)-1: # 9
                        if data[i+1][j+1] != '#':
                            data[i+1][j+1] += 1
                if i < len(data)-1: # 8
                    if data[i+1][j] != '#':
                        data[i+1][j] += 1
            for k in range(len(data)):
                print(data[k])
            print("------------------")
    print(data)
    A = sum(list(filter(lambda x:type(x) == int, sum(data, []))))
            
    return [count, A]

A = solution([[0, 0, '#', '#'], ['#', '#', 0, '#'], [0, '#', '#', 0]])
print(A)
