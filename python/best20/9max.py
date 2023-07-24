def solution(data):
    Max = 0
    Min = 0
    count = 0
    L = []
    copydata = data[:]
    copydata = sorted(copydata)
    Min = copydata[0]
    if copydata[len(data)-1] == data[len(data)-1]:
        data.remove(data[len(data)-1])
        copydata.remove(copydata[len(copydata)-1])
    for i in data:
        Max = i
        while data.index(Min) < i:
            if count == len(data)-1:
                break
            count += 1
            Min = copydata[count]
        L.append(Min-i)       
    return max(L)
A = solution([58000, 58700, 55300, 54200, 53600, 52700, 57700, 61100])
print(A)
