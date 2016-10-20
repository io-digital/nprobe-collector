package processor

import (
	"github.com/io-digital/nprobe-collector/structure"
)

type Processor interface {
	ProcessData(flowSetHeaderStruct structure.ProcessingFuncArgs, ack *bool) error
}