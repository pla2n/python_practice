#import sys

#N = int(input())
#data = []
#scale = {}
#num = []
#for i in range(N):
#    data.append(sys.stdin.readline().rstrip())
    
## data = sorted(data, key=lambda x:len(x), reverse=True)
#for i in range(N):
#    for j in range(len(data[i])):
#        if data[i][j] in scale:
#            scale[data[i][j]] += 10 **(len(data[i])-j-1)
#        else:
#            scale[data[i][j]] = 10 **(len(data[i])-j-1)

#for val in scale.values():
#    num.append(val)

#num.sort(reverse=True)

#Sum = 0
#count = 9
#for i in num:
#    Sum += i * count
#    count -= 1
#print(Sum)

import sys
input = sys.stdin.readline

N = int(input())

L = [list(map(str, input().strip())) for _ in range(N)]
L.sort(key=lambda x:len(x), reverse=True)
sL = {}
rL = []
result = 0
count = 9

for i in range(N):
    for j in range(len(L[i])):
        if L[i][j] in sL:
            sL[L[i][j]] += 10 ** (len(L[i]) - (j+1))
        else:
            sL[L[i][j]] = 10 ** (len(L[i]) - (j+1))
for i in sL.values():
    rL.append(i)
rL.sort(reverse=True)
for i in rL:
    result += count * i
    count -= 1
print(result)