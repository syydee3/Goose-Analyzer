package models

type GoosePacket struct {
	DstMAC         [6]byte
	SrcMAC         [6]byte
	VLAN           bool
	VlanPR         int
	VlanID         int
	AppID          int
	GoLen          int
	Simulated      bool
	GocbRef        string
	TimeToLive     int
	DatSet         string
	GoID           string
	Time           int64
	StNum          uint32
	SqNum          uint32
	Simulation     bool
	ConfRev        int
	NdsCom         bool
	DatasetEntries int
}

type ICDGoose struct {
	IEDName      string
	LDName       string
	GCBName      string
	DstMAC       [6]byte
	VLAN         bool
	VlanID       int
	VlanPR       int
	AppID        int
	DatSet       string
	GoID         string
	ConfRev      int
	NumDatSetEnt int
}

type GooseFlag struct {
	ConfiguredGoose      bool
	GhostGoose           bool
	SqNumErr             bool
	StNumErr             bool
	ConfRevChng          bool
	ConfRevErr           bool
	VprChng              bool
	VidChng              bool
	VlanAdded            bool
	VlanRemoved          bool
	SrcMacErr            bool
	ClockFailure         bool
	ClockRecovery        bool
	ClockSync            bool
	ClockInvalidAccuracy bool
	DatasetEmp           bool
	NdsComm              bool
	DuplicateGoose       bool
	NoERR                bool
}

type AlertEvent struct {
	Timestamp string         `json:"timestamp"`
	Severity  string         `json:"severity"`
	Error     string         `json:"error"`
	Message   string         `json:"message"`
	Context   map[string]any `json:"context"`
}

type HistoryItem struct {
	Filename  string `json:"filename"`
	Filepath  string `json:"filepath"`
	Timestamp string `json:"timestamp"`
}

type WSMessage struct {
	Type    string `json:"type"`
	Payload any    `json:"payload"`
}
