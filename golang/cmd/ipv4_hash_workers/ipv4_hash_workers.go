package main

import (
	"math"
	"sync"
	"time"

	"alea.net/xp/ipv4_hash/internal/common"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

const numWorkers = 12
const batchSize = 100_000
const displayModulo = 100_000_000 // Should we divisible by batchSize

var maxJobBuffer = int(math.Pow(2, 20))

type BatchRange struct {
	min int
	max int
}

var waitingGroup sync.WaitGroup

func processCheckTask(targetSet map[string]bool, tasks <-chan BatchRange, results chan<- int) {
	defer waitingGroup.Done()
	for batchRange := range tasks {
		for ip := batchRange.min; ip < batchRange.max; ip++ {
			candidate := common.GenerateIPv4String(ip)
			common.CheckCandidate(targetSet, candidate)
		}
		results <- batchRange.max - batchRange.min
	}
}

func countResults(results <-chan int) {
	count := 0
	startTime := time.Now()
	for c := range results {
		count += c
		if count%displayModulo == 0 {
			lenChan := len(results)
			t := time.Now()
			elapsed := t.Sub(startTime)
			p := message.NewPrinter(language.English)
			p.Printf("=> Count: %d after %v, chan len: %v\n", count, elapsed, lenChan)
		}
	}
}

func main() {

	targetSet := common.GenerateTestTargetSet()
	maxIP := int(math.Pow(2, 32))
	tasks := make(chan BatchRange, maxJobBuffer)
	results := make(chan int, maxJobBuffer)

	waitingGroup.Add(numWorkers)

	for i := 0; i < numWorkers; i++ {
		go processCheckTask(targetSet, tasks, results)
	}

	go countResults(results)

	ip := 0
ipLoop:
	for {
		if ip+batchSize < maxIP {
			tasks <- BatchRange{min: ip, max: ip + batchSize}
			ip += batchSize
		} else {
			tasks <- BatchRange{min: ip, max: maxIP}
			break ipLoop
		}

	}

	close(tasks)

	waitingGroup.Wait()

}
