import itertools
import copy

def solution(data):
    for k in range(data[2]):
        CL = []
        G = copy.deepcopy(data[3])
        for i in range(data[1]):
            for j in range(data[0]):
                if G[i][j] == 1:
                    if i > 0 and ([i-1, j] not in CL):
                        if G[i-1][j] == 1:
                            data[3][i-1][j] = -1
                            CL.append([i-1, j])
                        elif G[i-1][j] == 0:
                            data[3][i-1][j] = 1
                            CL.append([i-1, j])
                    if i < data[1]-1 and ([i+1, j] not in CL):
                        if G[i+1][j] == 1:
                            data[3][i+1][j] = -1
                            CL.append([i+1, j])
                        elif G[i+1][j] == 0:
                            data[3][i+1][j] = 1
                            CL.append([i+1, j])
                    if j > 0 and ([i, j-1] not in CL):
                        if G[i][j-1] == 1:
                            data[3][i][j-1] = -1
                            CL.append([i, j-1])
                        elif G[i][j-1] == 0:
                            data[3][i][j-1] = 1
                            CL.append([i, j-1])
                    if j < data[0]-1 and ([i, j+1] not in CL):
                        if G[i][j+1] == 1:
                            data[3][i][j+1] = -1
                            CL.append([i, j+1])
                        elif G[i][j+1] == 0:
                            data[3][i][j+1] = 1
                            CL.append([i, j+1])
                
                    
        print(data[3])
        if k == data[2]-1:
            return sum(x.count(1) for x in data[3])
        
    
A = solution([7, 5, 4, [[0, 0, 0, 0, 0, 0, 1], [0, 0, 0, 0, 0, 1, 0], [0, 0, 1, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0]]])
print(A)
