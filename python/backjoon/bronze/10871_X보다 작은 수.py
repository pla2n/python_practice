n, x = map(int, input().split())
L = list(map(int, input().split()))

for l in L:
    if l < x:
        print(l, end=' ')