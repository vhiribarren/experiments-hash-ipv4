package main

import (
	"math"
	"time"

	"alea.net/xp/ipv4_hash/internal/common"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

const displayModulo = 10_000_000

func main() {

	targetSet := common.GenerateTestTargetSet()
	startTime := time.Now()
	maxIP := int(math.Pow(2, 32))

	for ip := 0; ip < maxIP; ip++ {
		candidate := common.GenerateIPv4String(ip)
		common.CheckCandidate(targetSet, candidate)
		if ip%displayModulo == 0 {
			t := time.Now()
			elapsed := t.Sub(startTime)
			p := message.NewPrinter(language.English)
			p.Printf("=> Count: %d after %v\n", ip, elapsed)
		}
	}

}
