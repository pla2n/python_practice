n = list(map(int, input().split()))

acount = 0
dcount = 0

for i in range(1, 9):
    if n[i-1] == i:
        acount += 1
        if acount == 8:
            print("ascending")
    elif n[8-i] == i:
        dcount += 1
        if dcount == 8:
            print("descending")
if acount != 8 and dcount != 8:
    print("mixed")