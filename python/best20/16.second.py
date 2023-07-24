def solution(data):
    L = []
    for i in range(len(data)):
        L.append(data[i].split('-'))
        print(L)
    
    return data
A = solution(['하나-둘', '둘-셋', '셋-넷', '하나-다섯', '여섯-일곱'])
print(A)
