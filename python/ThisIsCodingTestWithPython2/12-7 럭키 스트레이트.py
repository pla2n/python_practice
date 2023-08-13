n = list(map(int, input()))

c = len(n)//2
a = n[:c]
b = n[c:]
if sum(a) == sum(b):
    print("LUCKY")
else:
    print("READY")