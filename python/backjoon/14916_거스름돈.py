1N = int(input())
M = int(N / 5)

while M >= 0:
    if (N - 5 * M) % 2 == 0:
        break
    else:
        M -= 1
if M < 0:
    count = -1
else:
    count = int(M + (N - 5 * M) / 2)
print(count)
