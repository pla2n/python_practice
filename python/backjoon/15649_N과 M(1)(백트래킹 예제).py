import sys
input = sys.stdin.readline

N, M = map(int, input().split()) # 백트래킹은 N이 10까지여야함(시간복잡도 때문에)
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
            check[i] = False # 재귀함수 쓴 후 중복 방지를 위해 재귀함수 쓰기 전으로 함수를 되돌려줌
            result.pop()

BT(0)


