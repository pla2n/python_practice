sent = input().upper()
L = [0 for i in range(26)] # 알파벳 각각에 해당하는 리스트를 다 만들어 줌
for i in sent :
    L[ord(i)-65] += 1

tmp = max(L)
if L.count(tmp) > 1 :
    print("?")
else :
    print("%s"%chr(L.index(tmp)+65))