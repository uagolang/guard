package utils

func Contains[T comparable](s []T, value T) bool {
	for _, item := range s {
		if item == value {
			return true
		}
	}

	return false
}

func Map[T any, R any](s []T, fn func(item T, index int) R) []R {
	res := make([]R, len(s))
	for i, item := range s {
		res[i] = fn(item, i)
	}

	return res
}

func FlatMap[T any, R any](input []T, fn func(T) []R) []R {
	var result []R
	for _, v := range input {
		result = append(result, fn(v)...)
	}

	return result
}

func SliceElem[T any](slice []T, index int, defaultValue T) T {
	if index >= 0 && index < len(slice) {
		return slice[index]
	}

	return defaultValue
}

func Find[T any](input []T, fn func(T) bool) (T, bool) {
	var zero T
	for _, v := range input {
		if fn(v) {
			return v, true
		}
	}

	return zero, false
}

func Filter[T any](slice []T, fn func(T) bool) []T {
	result := make([]T, 0)
	for _, v := range slice {
		if fn(v) {
			result = append(result, v)
		}
	}
	return result
}
