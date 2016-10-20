package function

import (
	"log"
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"encoding/json"
	"github.com/io-digital/nprobe-collector/structure"
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

func GetDbConfig(fileLocation string) (structure.DbConfiguration) {

	configValues, err := ioutil.ReadFile(fileLocation)

	if err != nil {
        log.Fatal("Processor error:", err)
    }

	dbConfig := structure.DbConfiguration{}

	err = json.Unmarshal(configValues, &dbConfig)
    if err != nil {
        log.Fatal("Processor error:", err)
    }

    return dbConfig
}

func GetProcessorConfig() (structure.ProcessorConfiguration) {

	configValues, err := ioutil.ReadFile("config/processor.json")

	if err != nil {
        log.Fatal("Processor error:", err)
    }

	processorConfig := structure.ProcessorConfiguration{}

	err = json.Unmarshal(configValues, &processorConfig)
    if err != nil {
        log.Fatal("Processor error:", err)
    }

    return processorConfig
}