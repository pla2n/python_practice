array = [7, 5, 9, 0, 3, 1, 6, 2, 4, 8]

for i in range(len(array)): # 선택 정렬 가장 작은 값 찾는데 유리 시간 복잡도 O(N^2)
    min_index = i
    for j in range(i+1, len(array)):
        if array[j] < array[min_index]:
            min_index = j # 계속해서 가장 작은 값을 찾아서 앞으로 둠
    array[i], array[min_index] = array[min_index], array[i]
print("Selection Sort", array)

array = [7, 5, 9, 0, 3, 1, 6, 2, 4, 8]

for i in range(1, len(array)): # 삽입 정렬 정렬이 어느정도 되어 있다면 시간 복잡도가 O(N) 아니면 O(N^2)
    for j in range(i, 0, -1):
        if array[j-1] > array[j]:
            array[j-1], array[j] = array[j], array[j-1] # j번째 array를 하나하나 비교해 가며 앞으로 보냄
        else:
            break
print("Insertion Sort", array)

array = [7, 5, 9, 0, 3, 1, 6, 2, 4, 8]

def quick_sort(array, start, end): # 퀵 정렬
    if start >= end:
        return
    pivot = start # 기준
    left = start+1
    right = end
    while left <= right:
        while left <= end and array[left] <= array[pivot]: # 피벗보다 큰 데이터를 찾을 때까지 반복
            left += 1
        while right > start and array[right] >= array[pivot]: # 피벗보다 작은 데이터를 찾을 떄까지 반복
            right -= 1

        if left > right:
            array[right], array[pivot] = array[pivot], array[right] # 엇갈렸기 때문에 피봇을 자기의 위치에 둠
        else:
            array[right], array[left] = array[left], array[right] # 위 while문을 만족한 경우 정렬

    quick_sort(array, start, right-1)
    quick_sort(array, right+1, end)

quick_sort(array, 0, len(array)-1)
print("Quick Sort", array)

array = [7, 5, 9, 0, 3, 1, 6, 2, 9, 1, 4, 8, 0, 5, 2]

count = [0] * (max(array) + 1)

for i in range(len(array)):
    count[array[i]] += 1
for i in range(len(count)):
    for j in range(array[i]):
        print(i, end=' ')