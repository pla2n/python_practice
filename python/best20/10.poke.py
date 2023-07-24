import itertools
def solution(data):
    if not data:
        return "기본 포케가 제공됩니다."
    Index = ['연어', '참치', '닭가슴살', '베이컨', '버섯']
    L = [0]*data[0]
    TL = []
    if len(data[1]) > 0:
        data[1] = [ingredient.strip() for ingredient in data[1].split(",")]
        for i in range(len(data[1])):
            L[i] = data[1][i]
            Index.remove(data[1][i])
    if data[0] - len(data[1]) == 1:
        for i in range(len(Index)):
            L[data[0]-1] = Index[i]
            TL.append(L[:])
            L.pop()
            L.append(0)
    else:
        while 0 in L:
            L.remove(0)
        TTL = []
        CL = list(itertools.combinations(Index, data[0] - len(data[1])))
        CL = [list(c) for c in CL]
        for i in CL:
            TTL.append(L + i)
        return TTL
    return TL
        
    
A = solution([])
print(A)
