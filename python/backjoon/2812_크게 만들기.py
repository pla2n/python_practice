import sys
input = sys.stdin.readline
N, K = map(int, input().split())
List = input().rstrip()
stack = []
for L in List:
    while stack and stack[-1] < L and K > 0:
        print(stack[-1], L)
        stack.pop()
        print(stack)
        K -= 1
    stack.append(L)
if K > 0:
    print(''.join(stack[:-K]))
else:
    print(''.join(stack))
