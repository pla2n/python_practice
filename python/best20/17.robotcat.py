def solution(data):
    L = []
    for i in data[1]:
        if i not in data[0]:
            L.append(i)
    return sorted(L)
        
    
A = solution([[102, 21, 38, 52, 219, 63, 1, 9, 35], [36, 9, 95, 32, 7, 52, 102]])
print(A)
