package function

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func PrintData(buffer []byte) {

	for i, data := range buffer {
		fmt.Println(i, ":", data)
	}
}

func ReadUint16(data []byte) (ret uint16) {
	buf := bytes.NewBuffer(data)
	binary.Read(buf, binary.BigEndian, &ret)
	return
}

func ReadUint32(data []byte) (ret uint32) {
	buf := bytes.NewBuffer(data)
	binary.Read(buf, binary.BigEndian, &ret)
	return
}

func ReadUint64(data []byte) (ret uint64) {
	buf := bytes.NewBuffer(data)
	binary.Read(buf, binary.BigEndian, &ret)
	return
}

func ParseConfiguration() (string){

	return "test"
}