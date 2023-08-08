import sys
import copy
from collections import deque
input = sys.stdin.readline

n = int(input())
indegree = [0] * (n+1)
L = [[0] for _ in range(n+1)]
time = [0] * (n+1)
for i in range(1, n+1):
    data = list(map(int, input().split()))
    time[i] = data[0] # 각각의 단일 소요 시간을 time에 저장
    for j in data[1:-1]: # time을 제외한 다른 요소들을 L에 더해주고, indegree를 통해 L에 몇개가 있는지 계산
        indegree[i] += 1
        L[j].append(i)

def topology_sort():
    result = copy.deepcopy(time)
    q = deque()
    for i in range(1, n+1):
        if indegree[i] == 0:
            q.append(i) # 진입 차수가 0인 노드를 큐에 삽입

    while q:
        now = q.popleft()
        for i in L[now]: # 소요 시간이 L[now]인 집한 안에서 반복
            # print("1 ", result, now, i, L)
            result[i] = max(result[i], result[now] + time[i]) # 모든 요소가 result[now] 만큼의 선수강 강의가 있음
            # print("2 ", result, time)
            indegree[i] -= 1
            if indegree[i] == 0:
                q.append(i)
    for i in range(1, n+1):
        print(result[i])

topology_sort()
'''
5
10 -1
10 1 -1
4 1 -1
4 3 1 -1
3 3 -1
'''