import sys

N = list(sys.stdin.readline().strip())
count = 0
for i in range(len(N)):
    if count == 0 and N[i] == 'X':
        count += 1
    else:
        if N[i-1] == N[i] == 'X' and count > 0:
            count += 1
            if count == 4:
                N[i-3:i+1] = ['A', 'A', 'A', 'A']
                count = 0
            if i == len(N)-1:
                if count > 1:
                    N[i-1:i+1] = ['B', 'B']
        else:
            if count == 4:
                N[i-4:i] = ['A', 'A', 'A', 'A']
                count = 0
            elif (count < 4) and (count > 1):
                N[i-2:i] = ['B', 'B']
                count = 0
N = ''.join(N)
if 'X' in N:
    print('-1')
else:
    print(N)
