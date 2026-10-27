package analyzer

import (
	"bytes"
	"encoding/binary"

	"github.com/syydee3/Goose-Analyzer/pkg/models"
)

func ParsePacket(packet []byte) (models.GoosePacket, bool) {
	var g models.GoosePacket
	pktLen := len(packet)
	if pktLen < 22 {
		return g, false
	}

	offset := 0
	copy(g.DstMAC[:], packet[0:6])
	offset += 6
	copy(g.SrcMAC[:], packet[6:12])
	offset += 6

	// Проверка 802.1Q VLAN тега (0x8100)
	if packet[12] == 0x81 && packet[13] == 0x00 {
		g.VLAN = true
		vlanHead := int(packet[14])
		g.VlanPR = (vlanHead >> 5) & 0x04
		vlanHead = (vlanHead << 8) + int(packet[15])
		g.VlanID = vlanHead & 0xFFF
		offset += 6
	} else {
		g.VlanPR = 0
		g.VlanID = 0
		if packet[12] == 0x88 && packet[13] == 0xb8 {
			offset += 2
		}
	}

	if offset+4 > pktLen {
		return g, false
	}

	// AppID и Length
	g.AppID = int(packet[offset])<<8 | int(packet[offset+1])
	offset += 2
	g.GoLen = int(packet[offset])<<8 | int(packet[offset+1])

	if offset+10 < pktLen {
		if packet[offset+8] == 0x80 {
			offset += 8
		} else if packet[offset+9] == 0x80 {
			offset += 9
		} else if packet[offset+10] == 0x80 {
			offset += 10
		}
	}

	// 0x80: gocbRef
	if offset+2 <= pktLen && packet[offset] == 0x80 {
		currLen := int(packet[offset+1])
		offset += 2
		if offset+currLen <= pktLen {
			g.GocbRef = cleanCString(packet[offset : offset+currLen])
			offset += currLen
		}
	}

	// 0x81: timeAllowedtoLive
	if offset+2 <= pktLen && packet[offset] == 0x81 {
		currLen := int(packet[offset+1])
		offset += 2
		if offset+currLen <= pktLen {
			g.TimeToLive = readUintVar(packet[offset : offset+currLen])
			offset += currLen
		}
	}

	// 0x82: datSet
	if offset+2 <= pktLen && packet[offset] == 0x82 {
		currLen := int(packet[offset+1])
		offset += 2
		if offset+currLen <= pktLen {
			g.DatSet = cleanCString(packet[offset : offset+currLen])
			offset += currLen
		}
	}

	// 0x83: goID
	if offset+2 <= pktLen && packet[offset] == 0x83 {
		currLen := int(packet[offset+1])
		offset += 2
		if offset+currLen <= pktLen {
			g.GoID = cleanCString(packet[offset : offset+currLen])
			offset += currLen
		}
	}

	// 0x84: t (Timestamp 8 bytes)
	if offset+2 <= pktLen && packet[offset] == 0x84 {
		currLen := int(packet[offset+1])
		offset += 2
		if currLen >= 8 && offset+8 <= pktLen {
			g.Time = int64(binary.BigEndian.Uint64(packet[offset : offset+8]))
			offset += currLen
		} else if offset+currLen <= pktLen {
			offset += currLen
		}
	}

	// 0x85: stNum
	if offset+2 <= pktLen && packet[offset] == 0x85 {
		currLen := int(packet[offset+1])
		offset += 2
		if offset+currLen <= pktLen {
			g.StNum = uint32(readUintVar(packet[offset : offset+currLen]))
			offset += currLen
		}
	}

	// 0x86: sqNum
	if offset+2 <= pktLen && packet[offset] == 0x86 {
		currLen := int(packet[offset+1])
		offset += 2
		if offset+currLen <= pktLen {
			g.SqNum = uint32(readUintVar(packet[offset : offset+currLen]))
			offset += currLen
		}
	}

	// 0x87: simulation
	if offset+3 <= pktLen && packet[offset] == 0x87 {
		g.Simulation = packet[offset+2] != 0
		offset += 3
	}

	// 0x88: confRev
	if offset+2 <= pktLen && packet[offset] == 0x88 {
		currLen := int(packet[offset+1])
		offset += 2
		if offset+currLen <= pktLen {
			g.ConfRev = readUintVar(packet[offset : offset+currLen])
			offset += currLen
		}
	}

	// 0x89: ndsCom
	if offset+3 <= pktLen && packet[offset] == 0x89 {
		g.NdsCom = packet[offset+2] != 0
		offset += 3
	}

	// 0x8a: numDatSetEntries
	if offset+2 <= pktLen && packet[offset] == 0x8a {
		currLen := int(packet[offset+1])
		offset += 2
		if offset+currLen <= pktLen {
			g.DatasetEntries = readUintVar(packet[offset : offset+currLen])
			offset += currLen
		}
	}

	return g, true
}

func readUintVar(b []byte) int {
	val := 0
	for _, v := range b {
		val = (val << 8) | int(v)
	}
	return val
}

func cleanCString(b []byte) string {
	if idx := bytes.IndexByte(b, 0); idx != -1 {
		return string(b[:idx])
	}
	return string(b)
}
