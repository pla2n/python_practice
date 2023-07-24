import itertools
def solution(data):
    count = 1
    while True:
        data[0] = data[0] * count
        L = itertools.combinations(data[0], count)
        for i in L:
            if sum(i) == data[1]:
                return count
        count += 1
        

A = solution([[6, 2, 4, 8, 32], 50])
print(A)
