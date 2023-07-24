import sys
input = sys.stdin.readline

N, M = map(int, input().split()) # ��Ʈ��ŷ�� N�� 10����������(�ð����⵵ ������)
check = [False] * (N+1)
result = []
def BT(num):
    if num == M:
        print(' '.join(map(str, result)))
        return
    for i in range(1, N+1):
        if check[i] == False:
            check[i] = True
            result.append(i)
            BT(num+1)
            check[i] = False # ����Լ� �� �� �ߺ� ������ ���� ����Լ� ���� ������ �Լ��� �ǵ�����
            result.pop()

BT(0)


