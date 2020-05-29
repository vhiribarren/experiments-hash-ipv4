package common

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

var targets = []string{
	"52ab14a48cb941963a498faefd02b1090ebfccfe47f07d5452628d8280b60154", // 1.0.0.0
	"f5047344122f0dee9974ba6761e61c6b8649e1f3968d13a635ebbf7be53a3a0d", // 10.0.0.1
	"12ca17b49af2289436f303e0166030a21e525d266e209267433801a8fd4071a0", // 127.0.0.1
	"37d7a80604871e579850a658c7add2ae7557d0c6abcc9b31ecddc4424207eba3", // 192.168.0.1
	"19e36255972107d42b8cecb77ef5622e842e8a50778a6ed8dd1ce94732daca9e", // 0.0.0.0
	"c4249e36619119f4caee1035f63e28b80809a6e7643feb27305a84b0129a12d0", // 254.0.0.0
	"f45462bf3cd12ea2b347f32f6c4d0a0d36e01694de332b307af90d42951c5bd6", // 255.255.255.255
}

func GenerateTestTargetSet() map[string]bool {
	set := map[string]bool{}
	for _, target := range targets {
		set[target] = true
	}
	return set
}

func GenerateIPv4String(ip int) string {
	partA := (ip & 0xFF000000) >> 24
	partB := (ip & 0x00FF0000) >> 16
	partC := (ip & 0x0000FF00) >> 8
	partD := (ip & 0x000000FF) >> 0

	var buffer strings.Builder
	buffer.Grow(15)
	buffer.WriteString(strconv.Itoa(partA))
	buffer.WriteString(".")
	buffer.WriteString(strconv.Itoa(partB))
	buffer.WriteString(".")
	buffer.WriteString(strconv.Itoa(partC))
	buffer.WriteString(".")
	buffer.WriteString(strconv.Itoa(partD))
	return buffer.String()

}

func CheckCandidate(targetSet map[string]bool, candidate string) {
	candidateBinaryHash := sha256.Sum256([]byte(candidate))
	candidateHash := hex.EncodeToString(candidateBinaryHash[:])
	if _, ok := targetSet[candidateHash]; ok {
		fmt.Printf("Found for %s: %s\n", candidateHash, candidate)
	}
}
