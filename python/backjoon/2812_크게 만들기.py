#import sys
#input = sys.stdin.readline
#N, K = map(int, input().split())
#List = input().rstrip()
#stack = []
#for L in List:
#    while stack and stack[-1] < L and K > 0:
#        print(stack[-1], L)
#        stack.pop()
#        print(stack)
#        K -= 1
#    stack.append(L)
#if K > 0:
#    print(''.join(stack[:-K]))
#else:
#    print(''.join(stack))

import sys
input = sys.stdin.readline

N, K = map(int, input().split())
List = input().rstrip()
stack = []

for L in List: # 리스트를 하나하나씩 다 비교해 줌
    while stack and stack[-1] < L and K > 0: # 마지막에 넣은 stack이 L보다 작으면, stack 하나씩 제거
        stack.pop()
        K -= 1
    stack.append(L)
if K > 0:
    print(''.join(stack[:-K]))
else:
    print(''.join(stack))
