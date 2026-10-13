package datasource

// cmpFunc is a 3-way comparison function generic over any type T.
// It returns:
//
//	-1 if a < b
//	 0 if a == b
//	 1 if a > b
type cmpFunc[T any] func(a, b T) int

// OrderedBy chains multiple 3-way comparison functions into one.
// It stops executing functions the moment a tie is broken.
func OrderedBy[T any](comparators ...cmpFunc[T]) func(a, b T) int {
	return func(a, b T) int {
		for _, compare := range comparators {
			if res := compare(a, b); res != 0 {
				return res // Tie broken! Return -1 or 1 immediately.
			}
		}
		return 0 // All criteria found the elements to be perfectly identical.
	}
}
