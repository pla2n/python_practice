s = list(input().strip())
L = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
for l in L:
    if l in s:
        print(s.index(l), end=' ')
    else:
        print(-1, end=' ')

a = input()

for i in range(97,123):
    print(a.find(chr(i)),end = " ")