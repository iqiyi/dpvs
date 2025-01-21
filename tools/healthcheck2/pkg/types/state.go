package types

const (
	UnKnown   State = 0
	Healthy   State = 1
	Unhealthy State = 2
)

type State int

func (state State) String() string {
	switch state {
	case Healthy:
		return "Healthy"
	case Unhealthy:
		return "Unhealthy"
	}
	return "Unknown"
}
