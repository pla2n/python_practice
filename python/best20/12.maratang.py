import itertools

def solutions(data):
    def removeindex(A, n):
        for i in range(len(A)):
            for j in range(n-1):
                if A[i][j+1] == (A[i][j]+1):
                    A[i] = ()
                    break
        A = list(filter(lambda x:x != (), A))
        return A
    
    index = [0,1, 2, 3, 4, 5, 6, 7]
    I4 = list(itertools.combinations(index, 4))
    I3 = list(itertools.combinations(index, 3))

    I4 = removeindex(I4, 4)
    I3 = removeindex(I3, 3)

    output = list(map(lambda x:sum([data[i] for i in x]), I4 + I3))
    return sorted(output, reverse=True)[0]
A = solutions([2, 4, 1, 3, 5, 8, 8, 6])
print(A)


import itertools

def solution(data):
    def removeindex(A, n):
        for i in range(len(A)):
            for j in range(n-1):
                if A[i][j]+1 == A[i][j+1]:
                    A[i] = ()
                    break
        A = list(filter(lambda x:x != (), A))
        return A

    index = [0, 1, 2, 3, 4, 5, 6, 7]
    I3 = list(itertools.combinations(index, 3))
    I4 = list(itertools.combinations(index, 4))

    I3 = removeindex(I3, 3)
    I4 = removeindex(I4, 4)

    output = list(map(lambda x:sum([data[i] for i in (x)]), I3+I4))
    return sorted(output, reverse=True)[0]

A = solution([2, 4, 1, 3, 5, 8, 8, 6])
print(A)
