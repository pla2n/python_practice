a, b, v = map(int, input().split())

if a == v:
    result = 1
else:
    if (v-a) % (a-b) == 0:
        result = (v - a) // (a - b) + 1
    else:
        result = (v-a) // (a-b) + 2
print(result)
