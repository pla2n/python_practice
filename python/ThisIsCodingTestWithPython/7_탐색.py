def sequential_search(n, target, array): # 순차 탐색 앞에서 부터 데이터를 하나 하나씩 확인
    for i in range(n): # 시간 복잡도 O(N) (최악의 경우)
        if array[i] == target:
            return i+1

def binary_search(array, target, start, end): # 이진 탐색 데이터가 정렬되어 있을 경우 사용 가능, 매우 빠르게 데이터 찾기 가능
    if start > end: #시간 복잡도 O(logN), 절반으로 나눈다는 점에서 퀵정렬과 같음
        return None
    mid = (start + end) // 2
    if array[mid] == target:
        return mid
    elif array[mid] > target: # 중간 값이 타겟보다 큰 경우 중간 값 아래 값들을 이진 탐색 다시 해 줌
        return binary_search(array, target, 0, mid-1)
    else: # 작은 경우 위 값들을 다시 이진탐색
        return binary_search(array, target, mid+1, end)


# 이진 탐색 트리: 이진 트리 왼쪽 자식 노드 < 부모 노드 < 오른쪽 자식 노드