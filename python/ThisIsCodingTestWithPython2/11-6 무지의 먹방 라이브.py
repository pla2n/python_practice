# https://school.programmers.co.kr/learn/courses/30/lessons/42891?language=python3

food_times = [3, 1, 2]
k = 5
answer = -1
count = 0
while count < k:
    if not food_times:
        answer = -1
        break
    for i in range(len(food_times)):
        if food_times[i] > 0:
            food_times[i] -= 1
            count += 1
            if count == k:
                answer = i
                break
    if 0 in food_times:
        food_times.remove(0)

print(k,"초에서 네트워크 장애가 발생했습니다.", answer, "번 음식을 섭취해야 할 때 중단되었으므로, 장애 복구 후에", answer, "번 음식부터 다시 먹기 시작하면 됩니다.");