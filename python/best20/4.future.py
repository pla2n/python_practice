import re
def solution(data):
    Train = {}
    Concern = {}
    og = 0
    cg = 0
    for i in data[0].split('.')[:-1]:
        print(i)
        key = re.findall(r'[a-zA-Z]', i)[0]
        value = re.findall(r'\d+', i)[0]
        if key in Train:
            Train[key] += int(value)
        else:
            Train[key] = int(value)
    for i in data[1].split('.')[:-1]:
        key = re.findall(r'[a-zA-Z]', i)[0]
        value = re.findall(r'\d+', i)[0]
        if key in Concern:
            Concern[key] += int(value)
        else:
            Concern[key] = int(value)
    for i in Train.keys():
        if i in Concern:
            og += Train[i] * Concern[i]
    if og == 0:
        return '미래가 보이지 않습니다.'
    maxTrain = max(Train.values())
    maxConcern = max(Concern.values())
    for i in Train:
        if Train[i] == maxTrain:
            Train[i] += 100
    for i in Concern:
        if Concern[i] == maxConcern:
            Concern[i] += 100

    for i in Train.keys():
        if i in Concern:
            cg += Train[i] * Concern[i]
    return f'최종 꿈의 설계는 원래 미래 {og}, 바뀐 미래 {cg}입니다. 이 수치대로 Vision을 만듭니다.'

A = solution(['100만큼 A를 훈련. 201 B. 120보다 이십만큼 더 B를 훈련했다.', '30만큼 A를 고민했다. 40만큼 B를 고민. 빙키는 A를 70만큼. C 10. D 10. A 10. z 10.'])
print(A)
