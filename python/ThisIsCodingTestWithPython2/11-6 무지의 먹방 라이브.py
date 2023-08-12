# https://school.programmers.co.kr/learn/courses/30/lessons/42891?language=python3

# 무지의 먹방 라이브
import heapq


food_times = [3, 1, 2]
k = 5
answer = -1
q = []
for i in range(len(food_times)):
    heapq.heappush(q, (food_times[i], i+1))

food = len(food_times)
previous = 0

while q:
    t = (q[0][0] - previous) * food
    if k >= t:
        k -= t
        previous, _ = heapq.heappop(q)
        food -= 1
    else:
        idx = k % food
        q.sort(key=lambda x:x[1])
        answer = q[idx][1]
        break
print(answer)
