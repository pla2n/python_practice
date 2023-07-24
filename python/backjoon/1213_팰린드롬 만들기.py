#import sys
#from collections import Counter

#w = list(map(str, sys.stdin.readline().strip()))
#w.sort()
#count = Counter(w)
#cnt = 0
#center = ""
#for i in count:
#    if count[i] % 2 != 0:
#        cnt += 1
#        center += i
#        w.remove(i)
#    if cnt > 1:
#        break
#if cnt > 1:
#    print("I'm Sorry Hansoo")
#else:
#    res = ""

#    for i in range(0, len(w), 2):
#        res += w[i]
#    print(res + center + res[::-1])

import sys
from collections import Counter
input = sys.stdin.readline

L = list(input().strip())
SL = {}
count = 0
center = ""

SL = Counter(L)

for k, l in SL.items():
    if l % 2 == 1:
        center = k
        L.remove(k)
        count += 1

if count > 1:
    print("I'm Sorry Hansoo")
else:
    result = ""
    L.sort()
    for i in range(0, len(L)-1, 2):
        result += L[i]
    print(result + center + result[::-1])