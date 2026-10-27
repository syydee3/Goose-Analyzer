package analyzer

import "github.com/syydee3/Goose-Analyzer/pkg/models"

func MatchGoose(accepted models.GoosePacket, stat models.ICDGoose) bool {
	if accepted.AppID != stat.AppID {
		return false
	}
	if accepted.DstMAC != stat.DstMAC {
		return false
	}

	var aGoID, sGoID [8]byte
	copy(aGoID[:], accepted.GoID)
	copy(sGoID[:], stat.GoID)
	return aGoID == sGoID
}

func CompareGoose(accepted, pool models.GoosePacket, state models.ICDGoose) models.GooseFlag {
	var flag models.GooseFlag

	flag.ConfiguredGoose = true
	flag.GhostGoose = false

	flag.DuplicateGoose = isDuplicate(accepted, pool)
	flag.SqNumErr = !flag.DuplicateGoose && isSqNumErr(accepted, pool)
	flag.StNumErr = isStNumErr(accepted, pool)
	flag.ConfRevChng = accepted.ConfRev != pool.ConfRev
	flag.ConfRevErr = accepted.ConfRev != state.ConfRev
	flag.NdsComm = accepted.NdsCom
	flag.SrcMacErr = accepted.SrcMAC != pool.SrcMAC

	flag.VlanAdded = accepted.VLAN && !pool.VLAN
	flag.VlanRemoved = !accepted.VLAN && pool.VLAN
	flag.VidChng = accepted.VlanID != pool.VlanID
	flag.VprChng = accepted.VlanPR != pool.VlanPR

	flag.ClockFailure = (accepted.Time & 0x40) != 0
	flag.ClockInvalidAccuracy = (accepted.Time & 0x1F) > 24
	flag.DatasetEmp = accepted.DatasetEntries == 0

	flag.NoERR = !flag.ConfRevErr &&
		!flag.DuplicateGoose &&
		!flag.SqNumErr &&
		!flag.StNumErr &&
		!flag.SrcMacErr

	return flag
}

func isDuplicate(g1, g2 models.GoosePacket) bool {
	return g1.AppID == g2.AppID && g1.SqNum == g2.SqNum && g1.StNum == g2.StNum
}

func isSqNumErr(g1, g2 models.GoosePacket) bool {
	if g1.SqNum == g2.SqNum+1 {
		return false
	}
	if g1.SqNum == 0 && g1.StNum == g2.StNum+1 {
		return false
	}
	return true
}

func isStNumErr(g1, g2 models.GoosePacket) bool {
	if g1.StNum == g2.StNum {
		return false
	}
	if g1.StNum == g2.StNum+1 && g1.SqNum == 0 {
		return false
	}
	return true
}
