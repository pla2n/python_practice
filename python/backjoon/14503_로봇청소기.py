import sys
input = sys.stdin.readline

N, M = map(int, input().split())
x, y, d = map(int, input().split())

L = [list(map(int, input().split())) for _ in range(N)]

dx = [-1, 0, 1, 0] # 2��ǥ��� �������� ��, ������, �Ʒ�, ���� ������ ����
dy = [0, 1, 0, -1]

count = 0

while 1:
    if L[x][y] == 0:
        L[x][y] = 2 # û���� ���� 2�� �ٲپ���
        count += 1
    sw = False
    for i in range(1, 5):
        nx = x + dx[d-i] # i�� �������ν� �ݽð�������� �̵�
        ny = y + dy[d-i]
        if 0 <= nx < N and 0 <= ny < M:
            if L[nx][ny] == 0:
                d = (d-i+4)%4
                y = ny 
                x = nx
                sw = True
                break
    if sw == False:
        nx = x - dx[d] # �ݴ� ����
        ny = y - dy[d]
        if 0 <= nx < N and 0 <= ny < M:
            if L[nx][ny] == 1: # ���� ���� ��� ����
                break
            else:
                x = nx # ���� �ƴѰ��, �ݴ���⿡�� �ٽ� ����
                y = ny
        else:
            break

print(count)