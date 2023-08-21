'''
import itertools
def solution(n, weak, dist):
    answer = 0
    L = [0] * n
    for i in range(n):
        if L[i] in weak:
            L[i] = i
    for i in range(1, len(dist)):
        for per in itertools.permutations(dist, i):
            for w in weak

    return answer
'''

from itertools import permutations
def solution(n, weak, dist):
    L = len(weak)
    cand = []
    weak_point = weak + [w+n for w in weak]  # 선형으로 만들기 위해 두배로 함
    for i, start in enumerate(weak): # index와 값 출력
        for friends in permutations(dist):  # 순열 이용
            count = 1 # 친구 수
            position = start # 현재 위치
            # 친구 조합 배치
            for friend in friends: # 순열로 만든 친구
                position += friend # 위치에 친구의 dist만큼 더해줌
                # 끝 포인트까지 도달 못했을 때
                if position < weak_point[i+L-1]:
                    count += 1  # 친구 더 투입
                    # 현재 위치보다 멀리 있는 취약지점 중 가장 가까운 위치로
                    position = [w for w in weak_point[i+1:i+L] if w > position][0]
                else:  # 끝 포인트까지 도달
                    cand.append(count)
                    break

    return min(cand) if cand else -1

# def solution(n, weak, dist):
#     L = len(weak)
#     cand = []
#     weak_point = weak + [w+n for w in weak]
#     for index, start in enumerate(weak):
#         for friends in permutations(dist):
#             count = 1
#             pos = start
#             for friend in friends:
#                 pos += friend
#                 if pos < weak_point[index+L-1]:
#                     count += 1
#                     pos = [w for w in weak_point[index+1:index+L] if w > pos][0]
#                 else:
#                     cand.append(count)
#                     break
#     return min(cand) if cand else -1


print(solution(12, [1, 5, 6, 10], [1, 2, 3, 4]))
