n = int(input())
L = [1]

for i in range(1, n):
    L.append(2*i)
    L.append(3*i)
    L.append(5*i)
L.sort()
L = list(set(L))
print(L[n-1])
