package raptor

// Ported from monad-bft/monad-raptor/src/ordered_set.rs.

// orderedSet maintains a sorted set of u16 values.
type orderedSet struct {
	data []uint16
}

// binarySearchThreshold is the empirically determined cutoff above which
// placementIndex uses binary search instead of a linear scan.
const binarySearchThreshold = 250

func (s *orderedSet) append(value uint16) {
	s.data = append(s.data, value)
}

// placementIndex returns the index of the lowest entry >= value, or len(data).
func (s *orderedSet) placementIndex(value uint16) int {
	if len(s.data) < binarySearchThreshold {
		for i, v := range s.data {
			if v >= value {
				return i
			}
		}
		return len(s.data)
	}
	if idx, ok := smallestIntegerSatisfying(0, len(s.data), func(p int) bool {
		return s.data[p] >= value
	}); ok {
		return idx
	}
	return len(s.data)
}

func (s *orderedSet) contains(value uint16) bool {
	i := s.placementIndex(value)
	return i < len(s.data) && s.data[i] == value
}

func (s *orderedSet) first() (uint16, bool) {
	if len(s.data) == 0 {
		return 0, false
	}
	return s.data[0], true
}

// insert adds value, returning false if already present.
func (s *orderedSet) insert(value uint16) bool {
	i := s.placementIndex(value)
	if i == len(s.data) || s.data[i] != value {
		s.data = append(s.data, 0)
		copy(s.data[i+1:], s.data[i:])
		s.data[i] = value
		return true
	}
	return false
}

// insertOrRemove toggles membership, returning true if value was inserted.
func (s *orderedSet) insertOrRemove(value uint16) bool {
	i := s.placementIndex(value)
	if i == len(s.data) || s.data[i] != value {
		s.data = append(s.data, 0)
		copy(s.data[i+1:], s.data[i:])
		s.data[i] = value
		return true
	}
	copy(s.data[i:], s.data[i+1:])
	s.data = s.data[:len(s.data)-1]
	return false
}

func (s *orderedSet) isEmpty() bool { return len(s.data) == 0 }

func (s *orderedSet) remove(value uint16) bool {
	i := s.placementIndex(value)
	if i < len(s.data) && s.data[i] == value {
		copy(s.data[i:], s.data[i+1:])
		s.data = s.data[:len(s.data)-1]
		return true
	}
	return false
}

func (s *orderedSet) len() int { return len(s.data) }

func (s *orderedSet) items() []uint16 { return s.data }
