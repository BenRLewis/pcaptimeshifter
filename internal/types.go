package internal

import "time"

type FileArgs struct {
	SourceFile   string
	ModifiedFile string
	OutputFile   string
}

type PacketNotFoundError struct {
	err string
}

func (e *PacketNotFoundError) Error() string {
	return "Packet not found"
}

type PacketPlaceholder struct {
	Timestamp time.Time
}
