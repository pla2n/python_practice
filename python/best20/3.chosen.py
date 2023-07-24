def solution(data):
    score = {}
    output = len(data)
    chose = int((output*3)/10)
    chosenone = 0
    chosenlist = []
    if chose < 1:
        return
    for i in data:
        S = sum(i[1:])
        if S in score:
            score[S] += i[0]
        else:
            score[S] = i[0]
    for i in sorted(list(score.items()), reverse=True):
        if chosenone <= output and len(i[1]) <= chose and chose != chosenone:
            chosenlist.extend(i[1])
            chosenone += len(i[1])
        elif len(i[1]) > chose:
            return chosenlist
    return sorted(chosenlist, reverse=True)

A = solution([['A', 25, 25, 25, 25], ['B', 10, 12, 13, 11], ['C', 24, 22, 23, 21], ['D', 13, 22, 16, 14]])
print(A)


def solution(data):
    score = {}
    chosen = 0
    output = len(data)
    choose = int((output * 3) / 10)
    chosenlist = []
    if choose < 1:
        return

    for i in data:
        S = sum(i[1:])
        if S in score:
            score[S] += i[0]
        else:
            score[S] = i[0]
    for i in sorted(list(score.items()), reverse=True):
        if chosen <= output and len[i[1]] <= choose and choose != chosen:
            chosenlist.extend(i[1])
            chosen += len(i[1])
        elif len(i[1]) > choose:
            return chosenlist
    return sorted(chosenlist, reverse=True)

    
