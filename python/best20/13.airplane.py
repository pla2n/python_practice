from itertools import combinations

def solution(data):
    if sum(data[0]) < data[1]:
        return -1
    count = 0
    temp = 0
    copydata = data[0][:]
    for i in copydata:
        if i >= data[1]:
            count += 1
            data[0].remove(i)
    while data[0]:
        print('-------------------')
        if len(data[0]) == 1:
            return count
        
        L = []
        for i in range(2, len(data[0])+1):
            for comb in combinations(data[0], i):
                if sum(comb) >= data[1]:
                    L.append([sum(comb), comb])
        if L == []:
            return count
        SL = sorted(L, key=lambda x:x[0])
        if SL[0][0] >= data[1]:
            count += 1
            data[0].remove(SL[0][1][0])
            data[0].remove(SL[0][1][1])
    return count

A = solution([[46, 26, 37, 32, 10], 30])
print(A)


from itertools import combinations
def solution(data):
    if sum(data[0]) < data[1]:
        return -1
    count = 0
    copydata = data[0][:]
    for i in copydata:
        if i > data[1]:
            count += 1
            data[0].remove(i)
    while data[0]:
        if len(data[0]) == 1:
            return count
        L = []
        for i in range(2, len(data[0])+1):
            for comb in combinations(data[0], i):
                if sum(comb) > data[1]:
                    L.append([sum(comb),comb])
        if L == []:
            return count
        SL = sorted(L, key=lambda x:x[0])
        if SL[0][0] >= data[1]:
            count += 1
            data[0].remove(SL[0][1][0])
            data[0].remove(SL[0][1][1])
    return count
A = solution([[46, 26, 37, 32, 10], 30])
print(A)
