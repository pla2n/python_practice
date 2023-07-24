import re

def solution(data):
    count = 0
    data = re.findall('([rev])(10|[1-9])', data)
    print(data)
    for i, j in data:
        count += int(j)
    count = str(count)
    return f'{count[0]}월 {count[1]}일'

solution('a10b9r1ce33uab8wc918v2cv11v9')


import re

def solution(data):
    count = 0
    data = re.findall('([rev])([1-9|10])', data)
    print(data)
    for i, j in data:
        count += int(j)
    count = str(count)
    return f'{count[0]}월 {count[1]}일'
    
solution('a10b9r1ce33uab8wc918v2cv11v9')
