import itertools

def solutions(data):
    A = list(itertools.combinations(data[0], 2))
    B = list(filter(lambda x:sum(x) == data[1], A))[0]
    return sorted([data[0].index(B[0]), data[0].index(B[1], data[0].index(B[0]+1))])


import itertools

def solutions(data):
    A = list(itertools.combinations(data[0], 2))
    B = list(filter(lambda x:sum(x) == data[1], A))[0]
    return sorted([data[0].index(B[0]), data[0].index(B[1], data[0].index(B[0]+1))])
