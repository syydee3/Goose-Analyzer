package analyzer

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/syydee3/Goose-Analyzer/pkg/models"
)

const FilterExp = "(vlan and ether proto 0x88b8)"

type Engine struct {
	staticConfig []models.ICDGoose
	goosesPool   []models.GoosePacket
	tcpClient    *TCPClient
	handle       *pcap.Handle
}

func NewEngine(cfg []models.ICDGoose, tcpClient *TCPClient, handle *pcap.Handle) *Engine {
	return &Engine{
		staticConfig: cfg,
		goosesPool:   make([]models.GoosePacket, len(cfg)),
		tcpClient:    tcpClient,
		handle:       handle,
	}
}

func OpenPcap(online bool, iface, dumpFile string) (*pcap.Handle, error) {
	var handle *pcap.Handle
	var err error

	if !online {
		handle, err = pcap.OpenOffline(dumpFile)
		if err != nil {
			return nil, fmt.Errorf("open dump %s: %w", dumpFile, err)
		}
		fmt.Printf("Successfully opened: %s\n", dumpFile)
	} else {
		handle, err = pcap.OpenLive(iface, 65536, true, time.Second)
		if err != nil {
			return nil, fmt.Errorf("open live %s: %w", iface, err)
		}
		fmt.Printf("Live capture opened on %s\n", iface)
	}

	if err := handle.SetBPFFilter(FilterExp); err != nil {
		handle.Close()
		return nil, fmt.Errorf("set filter %s: %w", FilterExp, err)
	}
	return handle, nil
}

func (e *Engine) Run(ctx context.Context) {
	e.runPrepPhase(ctx)
	e.runMainPipeline(ctx)
	e.tcpClient.EmitLoadStats()
	fmt.Println("Load stats sent via TCP")
}

func (e *Engine) runPrepPhase(ctx context.Context) {
	numSCD := len(e.staticConfig)
	foundGoose := make([]bool, numSCD)
	prepCounter, matchCounter := 0, 0

	fmt.Println("STARTING PREP")
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		data, _, err := e.handle.ReadPacketData()
		if err != nil {
			break
		}
		prepCounter++

		ret, ok := ParsePacket(data)
		if !ok {
			continue
		}

		for i := 0; i < numSCD; i++ {
			if MatchGoose(ret, e.staticConfig[i]) {
				if !foundGoose[i] {
					foundGoose[i] = true
					matchCounter++
					fmt.Printf(">>> FIRST PACKET for GOOSE %d (APPID 0x%04x) at packet %d\n", i, ret.AppID, prepCounter)
				}
				if e.goosesPool[i].SqNum == 0 || ret.SqNum != e.goosesPool[i].SqNum || ret.StNum != e.goosesPool[i].StNum || ret.ConfRev != e.goosesPool[i].ConfRev {
					e.goosesPool[i] = ret
				}
			}
		}

		if matchCounter == numSCD || prepCounter >= 500 {
			break
		}
	}
	fmt.Printf("PREP finished: processed %d packets, found %d of %d GOOSE\n", prepCounter, matchCounter, numSCD)
}

func (e *Engine) runMainPipeline(ctx context.Context) {
	fmt.Println("Starting MAIN LOOP with Sharded Goroutines")

	numWorkers := runtime.NumCPU()
	if numWorkers < 2 {
		numWorkers = 2
	}

	workerChans := make([]chan models.GoosePacket, numWorkers)
	var workersWG sync.WaitGroup

	for w := range numWorkers {
		ch := make(chan models.GoosePacket, 2048)
		workerChans[w] = ch
		workersWG.Go(func() {
			for pkt := range ch {
				e.evaluatePacket(pkt)
			}
		})
	}

	rawChan := make(chan []byte, 4096)
	var parsersWG sync.WaitGroup
	for range numWorkers {
		parsersWG.Go(func() {
			for raw := range rawChan {
				if pkt, ok := ParsePacket(raw); ok {
					shard := pkt.AppID % numWorkers
					if shard < 0 {
						shard = -shard
					}
					workerChans[shard] <- pkt
				}
			}
		})
	}

	for {
		select {
		case <-ctx.Done():
			goto shutdown
		default:
		}

		data, _, err := e.handle.ReadPacketData()
		if err != nil {
			break
		}
		buf := make([]byte, len(data))
		copy(buf, data)
		rawChan <- buf
	}

shutdown:
	close(rawChan)
	parsersWG.Wait()
	for w := range numWorkers {
		close(workerChans[w])
	}
	workersWG.Wait()
}

func (e *Engine) evaluatePacket(ret models.GoosePacket) {
	numSCD := len(e.staticConfig)
	left, right := 0, numSCD-1
	match := false

	for left <= right {
		mid := (left + right) / 2
		if ret.AppID < e.staticConfig[mid].AppID {
			right = mid - 1
		} else if ret.AppID > e.staticConfig[mid].AppID {
			left = mid + 1
		} else {
			start := mid
			for start > 0 && e.staticConfig[start-1].AppID == ret.AppID {
				start--
			}
			for i := start; i < numSCD && e.staticConfig[i].AppID == ret.AppID; i++ {
				if MatchGoose(ret, e.staticConfig[i]) {
					match = true
					prev := e.goosesPool[i]
					flag := CompareGoose(ret, prev, e.staticConfig[i])
					e.goosesPool[i] = ret
					e.tcpClient.EmitFlag(flag, ret)
					break
				}
			}
			break
		}
	}

	if !match {
		e.tcpClient.EmitGhost(ret)
	}
}
