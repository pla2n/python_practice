import sys

d = [0]*3001

X = int(sys.stdin.readline())
for i in range(2, X+1):
    d[i] = d[i-1] + 1
    if i % 5 == 0:
        d[i] = min(d[i], d[i//5]+1) # +1 해주는 이유는 숫자로 나누는 행위의 해당하는 횟수를 증가하기 때문임
    if i % 3 == 0:
        d[i] = min(d[i], d[i//3]+1)
    if i % 2 == 0:
        d[i] = min(d[i], d[i//2]+1)
print(d[X])