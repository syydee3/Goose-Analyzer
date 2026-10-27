package scl

import (
	"bufio"
	"cmp"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/syydee3/Goose-Analyzer/pkg/models"
)

func LoadConfig(path string) ([]models.ICDGoose, error) {
	if strings.HasSuffix(strings.ToLower(path), ".txt") {
		return loadFromGoDataTxt(path)
	}
	return loadFromSCD(path)
}

func loadFromSCD(scdPath string) ([]models.ICDGoose, error) {
	data, err := os.ReadFile(scdPath)
	if err != nil {
		return nil, fmt.Errorf("read scd: %w", err)
	}

	var sclData SCL
	if err := xml.Unmarshal(data, &sclData); err != nil {
		return nil, fmt.Errorf("unmarshal xml: %w", err)
	}

	iedMap := make(map[string]IED, len(sclData.IEDs))
	for _, ied := range sclData.IEDs {
		iedMap[ied.Name] = ied
	}

	var result []models.ICDGoose
	for _, sn := range sclData.Communication.SubNetworks {
		for _, ap := range sn.ConnectedAPs {
			for _, gse := range ap.GSEs {
				item := models.ICDGoose{
					IEDName: ap.IEDName,
					LDName:  gse.LDInst,
					GCBName: gse.CBName,
				}
				for _, p := range gse.Address.Ps {
					val := strings.TrimSpace(p.Value)
					switch p.Type {
					case "VLAN-ID":
						v, _ := strconv.ParseInt(val, 16, 32)
						item.VlanID = int(v)
						item.VLAN = true
					case "VLAN-PRIORITY":
						item.VlanPR, _ = strconv.Atoi(val)
					case "MAC-Address":
						item.DstMAC = parseMAC(val)
					case "APPID":
						v, _ := strconv.ParseInt(val, 16, 32)
						item.AppID = int(v)
					}
				}

				if ied, ok := iedMap[ap.IEDName]; ok && len(ied.AccessPoint.Server.LDevices) > 0 {
					ld := ied.AccessPoint.Server.LDevices[0]
					for _, c := range ied.AccessPoint.Server.LDevices {
						if c.Inst == gse.LDInst {
							ld = c
							break
						}
						if len(ld.LN0.GSEControls) > 0 {
							ctrl := ld.LN0.GSEControls[0]
							for _, c := range ld.LN0.GSEControls {
								if c.Name == gse.CBName {
									ctrl = c
									break
								}
							}
							item.DatSet = ctrl.DatSet
							item.ConfRev = ctrl.ConfRev
							item.GoID = ctrl.AppID
						}
						if len(ld.LN0.DataSets) > 0 {
							ds := ld.LN0.DataSets[0]
							for _, d := range ld.LN0.DataSets {
								if d.Name == item.DatSet {
									ds = d
									break
								}
							}
							item.NumDatSetEnt = len(ds.FCDA)
						}
					}
					result = append(result, item)
				}
			}
		}
	}

	slices.SortFunc(result, func(a, b models.ICDGoose) int {
		return cmp.Compare(a.AppID, b.AppID)
	})
	return result, nil
}

func loadFromGoDataTxt(txtpath string) ([]models.ICDGoose, error) {
	file, err := os.Open(txtpath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return nil, fmt.Errorf("empty goData.txt")
	}

	var result []models.ICDGoose
	for scanner.Scan() {
		words := strings.Fields(scanner.Text())
		if len(words) < 11 {
			continue
		}
		vlan := strings.EqualFold(words[4], "true") || words[4] == "1"
		vlanID, _ := strconv.Atoi(words[5])
		vlanPR, _ := strconv.Atoi(words[6])
		appID, _ := strconv.Atoi(words[7])
		confRev, _ := strconv.Atoi(words[9])
		datSetEnt, _ := strconv.Atoi(words[10])

		result = append(result, models.ICDGoose{
			IEDName:      words[0],
			LDName:       words[1],
			GCBName:      words[2],
			DstMAC:       parseMAC(words[3]),
			VLAN:         vlan,
			VlanID:       vlanID,
			VlanPR:       vlanPR,
			AppID:        appID,
			GoID:         words[8],
			ConfRev:      confRev,
			NumDatSetEnt: datSetEnt,
		})
	}

	slices.SortFunc(result, func(a, b models.ICDGoose) int {
		return cmp.Compare(a.AppID, b.AppID)
	})

	return result, scanner.Err()
}

func parseMAC(s string) [6]byte {
	var mac [6]byte
	clean := strings.NewReplacer("-", "", ":", "").Replace(strings.ToLower(s))
	if b, err := hex.DecodeString(clean); err == nil && len(b) == 6 {
		copy(mac[:], b)
	}
	return mac
}
