def quick_sort(array, start, end):
    pivot = start
    left = start + 1
    right = end
    while left <= right:
        while left <= end and array[left] < array[pivot]:
            left += 1
        while right > start and array[right] > array[pivot]:
            right -= 1
        if left > right:
            array[pivot], array[right] = array[right], array[pivot]
        else:
            array[pivot], array[left] = array[left], array[pivot]
    quick_sort(array, start, right-1)
    quick_sort(array, right+1, end)