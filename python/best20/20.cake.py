import itertools
def solution(data):
    L = {}
    OP = []
    count = 0
    for i in range(len(data[0][0])):
        L[data[0][0][i]] = [data[0][1][i], data[0][2][i]]
    L = sorted(L.items(), key=lambda x:x[1][1])
    for i in L:
        print(i[1][0])
        count += i[1][0]
        if count > data[1]:
            break
        else:
            OP.append(i[0])
    return OP
A = solution([[['딸기', '생크림', '밀가루', '버터'], [15, 8, 4, 20], [4, 3, 2, 1]], 40])
print(A)
