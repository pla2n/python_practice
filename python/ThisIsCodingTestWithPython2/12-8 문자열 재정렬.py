S = list(input())
S.sort()
string = []
integer = 0
for s in S:
    if s.isdigit() and isinstance(s, str): # 문자열이면서 정수인지 판별
        integer += int(s)
    elif isinstance(s, str):
        string.append(s)
for i in range(len(string)):
    print("".join(string[i]), end='')
print(integer)

'''
K1KA5CB7

AJKDLSI412K4JSJ9D
'''