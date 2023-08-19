# https://school.programmers.co.kr/learn/courses/30/lessons/42891?language=python3


# 무지의 먹방 라이브
import heapq
# def solution(food_times, k):
#     answer = -1
#     q = []
#     for i in range(len(food_times)):
#         heapq.heappush(q, (food_times[i], i+1))
#
#     food = len(food_times)
#     previous = 0
#
#     while q:
#         t = (q[0][0] - previous) * food
#         if k >= t:
#             k -= t
#             previous, _ = heapq.heappop(q)
#             food -= 1
#         else:
#             idx = k % food
#             q.sort(key=lambda x:x[1])
#             answer = q[idx][1]
#             break
#     return answer


def solution(food_times, k):
    answer = -1
    q = []
    for i in range(len(food_times)):
        heapq.heappush(q, (food_times[i], i+1))
    food = len(food_times)
    previous = 0
    while q:
        t = (q[0][0] - previous) * food # previous를 빼주는 이유는 원래 순서대로 먹기 때문에 previous만큼을 다른 곳에서도 먹어야 한다.
        if k >= t: # food는 남은 food의 갯수만큼 곱해줘야 현재 요소를 먹는 시간을 구할 수 있기 때문
            k -= t
            previous, _ = heapq.heappop(q)
            food -= 1
        else:
            idx = k % food
            q.sort(key=lambda x:x[1])
            answer = q[idx][1] # 정렬된 값에서 idx번째 값이 정답
            break

    return answer

rs = solution([3, 1, 2], 5)
print(rs)