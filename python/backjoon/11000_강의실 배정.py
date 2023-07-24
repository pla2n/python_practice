import heapq
import sys

n = int(sys.stdin.readline())
meetings = []

for i in range(n):
    start, end = map(int, sys.stdin.readline().split())
    meetings.append([start, end])

meetings.sort()

room = []
heapq.heappush(room, meetings[0][1])
print(meetings)
for i in range(1, n):
    if meetings[i][0] < room[0]:
        heapq.heappush(room, meetings[i][1])
    else:
        heapq.heappop(room)
        heapq.heappush(room, meetings[i][1])
    print(room)
print(len(room))
        
