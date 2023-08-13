import sys
input = sys.stdin.readline

n = int(input()) # 보드의 크기
K = int(input())
KL = []
L = []
for k in range(K): # 사과의 위치
    KL.append(map(int, input().split()))
l = int(input())
for li in range(l): # 방향 변환 횟수
    L.append(map(int, input().split()))
0