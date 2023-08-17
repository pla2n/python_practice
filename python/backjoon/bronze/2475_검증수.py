n = list(map(int, input().split()))
result = 0
for i in range(5):
    result += n[i]**2
print(result%10)