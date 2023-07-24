import sys

def merge_sort(start, end):
    global swap_cnt, ARR

    if start < end:
        mid = (start + end) // 2
        print("1------------------")
        merge_sort(start, mid)
        print("2------------------")
        merge_sort(mid + 1, end)

        front_idx, back_idx = start, mid + 1
        new_arr = []

        while front_idx <= mid and back_idx <= end: # 정상적인 배열일 때 반복
            if ARR[front_idx] <= ARR[back_idx]: # 앞에가 작거나 같을 때
                new_arr.append(ARR[front_idx])
                front_idx += 1 # 변경되어야할 위치 계산 (index)
                print("1", new_arr)
            else:
                new_arr.append(ARR[back_idx]) # 뒤에가 크므로 배열 변경하고 count 증가
                back_idx += 1
                swap_cnt += mid - front_idx + 1 # 스왑 횟수
                print("output", swap_cnt)
                print("2", new_arr)

        if front_idx <= mid: #완성 후 합치기 직전
            new_arr = new_arr + ARR[front_idx : mid + 1]
            print("3", new_arr)
        if back_idx <= end: # 완성 후 합치기 직전
            new_arr = new_arr + ARR[back_idx : end + 1]
            print("4", new_arr)

        for i in range(len(new_arr)):
            ARR[start + i] = new_arr[i]
            print("5", ARR)


if __name__ == "__main__":
    swap_cnt = 0
    N = int(sys.stdin.readline()) # 빠른 입력
    ARR = list(map(int, sys.stdin.readline().split()))
    merge_sort(0, N - 1)
    print(swap_cnt)
    print("2 4 3 5 1")
