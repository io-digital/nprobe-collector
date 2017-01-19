package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/rpc"
	"math"
	"time"
	"sync"
//	"os/exec"
	"github.com/io-digital/nprobe-collector/structure"
	"github.com/io-digital/nprobe-collector/function"
)

var (
	debugMode bool
	dataBuffer []map[string][]byte
	dataTemplates = make(map[uint16]map[string][]uint16)
	optionTemplates = make(map[uint16]map[string][]uint16)
	packetCount = 0
	flowSetHeaderReadDone = make(chan bool)
	flowSetRecordReadDone = make(chan bool)
	dataBufferFull = make(chan bool)
	optionDataBufferFull = make(chan bool)
	flowSetRecord []byte
	dataBufferLock sync.Mutex
	rpcClients []*rpc.Client
)

func readFlowSetHeader(reader *bufio.Reader, flowSetHeaderSlice []byte, flowSetHeaderStruct *structure.FlowSetHeader/*, done chan bool*/) {

	flowSetHeaderSlice = nil

	for i := 0; i < 20; {
		newByte, err := reader.ReadByte()

		if err == nil {
			flowSetHeaderSlice = append(flowSetHeaderSlice, newByte)
			i++

		} else if err == io.EOF {
			fmt.Printf("Number of Packets: %d\n", packetCount)
			fmt.Printf("Unexpected Error - readFlowSetHeader: %s", err)
			//flowSetHeaderSlice = nil
			flowSetHeaderReadDone <- false
			return
		} else {
			fmt.Println("Waiting for data")
		}
	}

	flowSetHeaderStruct.Version = function.ReadUint16(flowSetHeaderSlice[0:2])
	flowSetHeaderStruct.Records = function.ReadUint16(flowSetHeaderSlice[2:4])
	flowSetHeaderStruct.SystemUptime = function.ReadUint32(flowSetHeaderSlice[4:8])
	flowSetHeaderStruct.Timestamp =  time.Unix(int64(function.ReadUint32(flowSetHeaderSlice[8:12])), 0)

	if debugMode {
		fmt.Printf("FlowSet Header: NetFlow Version = %d, Number of Packets = %d, Time = %s \n", flowSetHeaderStruct.Version, flowSetHeaderStruct.Records, flowSetHeaderStruct.Timestamp)
	}

	packetCount++

	if(math.Remainder(float64(packetCount), 1000) == 0){
		fmt.Printf("Records processed: %d\n", packetCount)
	}

	flowSetHeaderReadDone <- true
}

func readFlowSetRecord(reader *bufio.Reader, flowSetRecord *[]byte) {

	flowSetIdLength, err := reader.Peek(4)

	if err != nil {
		fmt.Printf("Unexpected Error - readFlowSetRecord: %s", err)
		*flowSetRecord = nil
		flowSetRecordReadDone <- false
		return
	}

	flowSetLength := int(function.ReadUint16(flowSetIdLength[2:4]))

	if debugMode {
		fmt.Printf("FlowSet Record: FlowSetId = %d, Length = %d\n", function.ReadUint16(flowSetIdLength[0:2]), flowSetLength)
	}

	for i := 0; i < flowSetLength; {

		newByte, err := reader.ReadByte()

		if err == nil {
			*flowSetRecord = append(*flowSetRecord, newByte)
			i++
		} else if debugMode {
			fmt.Println("Waiting for data")
		}
	}

	flowSetRecordReadDone <- true
}

func parseFlowSetTemplate(flowSetTemplate []byte) {

	templates := flowSetTemplate[4:]

	for len(templates) > 0 {

		templateId := function.ReadUint16(templates[0:2])
		fieldCount := int(function.ReadUint16(templates[2:4]))
		templates = templates[4:]
		fieldTypeIndex := make([]uint16, 0)
		fieldLength := make([]uint16, 0)

		if debugMode {
			fmt.Printf("Parsing FlowSet Template: TemplateId = %d, Number of Fields = %d\n", templateId, fieldCount)
		}

		for i := 0; i < fieldCount; i++ {

			fieldTypeIndex = append(fieldTypeIndex, function.ReadUint16(templates[0:2]))
			fieldLength = append(fieldLength, function.ReadUint16(templates[2:4]))

			templates = templates[4:]
		}

		dataTemplates[templateId] = map[string][]uint16{
			"fieldTypeIndex": fieldTypeIndex,
			"fieldLength":    fieldLength,
		}
	}
}

func parseFlowSetOptions(flowSetOptions []byte) {

	template := flowSetOptions[4:]
	templateId := function.ReadUint16(template[0:2])
	optionScopeLength := int(function.ReadUint16(template[2:4]))/4
	optionLength := int(function.ReadUint16(template[4:6]))/4
	template = template[6:]

	scopeFieldTypeIndex := make([]uint16, 0)
	scopeFieldLength := make([]uint16, 0)
	optionFieldTypeIndex := make([]uint16, 0)
	optionFieldLength := make([]uint16, 0)

	if debugMode {
		fmt.Printf("Parsing FlowSet Options Template: TemplateId = %d, Option Scope Length = %d, Option Length = %d\n", templateId, optionScopeLength, optionLength)
	}

	for i := 0; i < optionScopeLength; i++ {

		scopeFieldTypeIndex = append(scopeFieldTypeIndex, function.ReadUint16(template[0:2]))
		scopeFieldLength = append(scopeFieldLength, function.ReadUint16(template[2:4]))

		template = template[4:]
	}

	for i := 0; i < optionLength; i++ {

		optionFieldTypeIndex = append(optionFieldTypeIndex, function.ReadUint16(template[0:2]))
		optionFieldLength = append(optionFieldLength, function.ReadUint16(template[2:4]))

		template = template[4:]
	}

	optionTemplates[templateId] = map[string][]uint16{
		"scopeFieldTypeIndex":  scopeFieldTypeIndex,
		"scopeFieldLength":     scopeFieldLength,
		"optionFieldTypeIndex": optionFieldTypeIndex,
		"optionFieldLength":    optionFieldLength,
	}
}

func parseFlowSetData(flowSetData []byte) {

	templateId := function.ReadUint16(flowSetData[0:2])
	dataTemplate, dataTemplateExists := dataTemplates[templateId]
	optionTemplate, optionTemplateExists := optionTemplates[templateId]

	if dataTemplateExists {

		if debugMode {
			fmt.Printf("Parsing FlowSet Data: TemplateId = %d, Packet Length = %d\n", templateId, len(flowSetData))
			fmt.Println("------------------------------------------------------------------------")
		}

		fieldValues := flowSetData[4:]

		dataBufferLock.Lock()
		dataBuffer = nil

		for len(fieldValues) >= 4 {

			packet := make(map[string][]byte, 0)

			for index, fieldLength := range dataTemplate["fieldLength"] {

				fieldMapIndex := dataTemplate["fieldTypeIndex"][index]
				fieldName := structure.NetFlowFieldTypes[fieldMapIndex]
				fieldValue := fieldValues[0:fieldLength]

				packet[fieldName] = fieldValue

				if debugMode {
					fmt.Printf("Name: %s, Length: %d, Value: %d\n", fieldName, fieldLength, fieldValue)
				}

				fieldValues = fieldValues[fieldLength:]
			}

			dataBuffer = append(dataBuffer, packet)
			if debugMode {
				fmt.Println("------------------------------------------------------------------------")
			}
		}

		dataBufferLock.Unlock()
		//data buffer is full for this flowset
		dataBufferFull <- true

	} else if optionTemplateExists {

		if debugMode {
			fmt.Printf("Parsing FlowSet Options Data: TemplateId = %d, Packet Length = %d\n", templateId, len(flowSetData))
			fmt.Println("------------------------------------------------------------------------")
		}

		fieldValues := flowSetData[4:]

		for index, fieldLength := range optionTemplate["scopeFieldLength"] {

			fieldMapIndex := optionTemplate["scopeFieldTypeIndex"][index]
			fieldName := structure.NetFlowScopeFields[fieldMapIndex]
			fieldValue := fieldValues[0:fieldLength]

			if debugMode {
				fmt.Printf("Name: %s, Length: %d, Value: %d\n", fieldName, fieldLength, fieldValue)
			}

			fieldValues = fieldValues[fieldLength:]
		}

		for index, fieldLength := range optionTemplate["optionFieldLength"] {

			fieldMapIndex := optionTemplate["optionFieldTypeIndex"][index]
			fieldName := structure.NetFlowFieldTypes[fieldMapIndex]
			fieldValue := fieldValues[0:fieldLength]

			if debugMode {
				fmt.Printf("Name: %s, Length: %d, Value: %d\n", fieldName, fieldLength, fieldValue)
			}

			fieldValues = fieldValues[fieldLength:]
		}
		if debugMode {
			fmt.Println("------------------------------------------------------------------------")
		}

		optionDataBufferFull <- true

	} else {

		fmt.Printf("templateId %d not found\n", templateId)
	}
}

func startProcessors(){

	processorConfig := function.GetProcessorConfig("config/processor.json")
	rpcClients = nil
	
	for _, processor := range processorConfig.Processors {

		fmt.Println("Processor Found:", processor.Name, "| Location:", processor.Location)
		var i = 1;

		for {
			client, err := rpc.Dial("tcp", "localhost:"+processor.TcpPort)

			if err != nil {
				time.Sleep(1000 * time.Millisecond)
	        	fmt.Println("attempt ", i)
	        	i++
			} else {
				rpcClients = append(rpcClients, client)
				fmt.Println("Communication with Processor Successful")
				break;
			}
		}
	}
}

func init(){

	debugPtr := flag.Bool("debug", false, "Outputs data as it is received")
	flag.Parse()

	debugMode = *debugPtr

	fmt.Println("Launching TCP server...")

	//Initialize processors
	startProcessors()
}

func main() {

	flowSetHeaderSlice := make([]byte, 20)
	flowSetHeader := structure.FlowSetHeader{}

	ln, err := net.Listen("tcp", ":2055")

	if err != nil {
		log.Fatalf("TCP Error: %s", err)
	}
	

	
	conn, err := ln.Accept()

	if err != nil {
		log.Fatalf("Connection Accept Error: %s", err)
	}

	reader := bufio.NewReader(conn)
	
	fmt.Println("Listening on and accepting connections on port 2055...")


	tempRes := make(chan *rpc.Call, 100)

	for {

		go readFlowSetHeader(reader, flowSetHeaderSlice, &flowSetHeader)
		<-flowSetHeaderReadDone

		for flowSetRecordCounter := 0; flowSetRecordCounter < int(flowSetHeader.Records); flowSetRecordCounter++ {

			flowSetRecord = nil

			go readFlowSetRecord(reader, &flowSetRecord)
			<-flowSetRecordReadDone

			flowSetId := function.ReadUint16(flowSetRecord)

			switch flowSetId {

			case 0:
				parseFlowSetTemplate(flowSetRecord)
			case 1:
				parseFlowSetOptions(flowSetRecord)
			default:

				go parseFlowSetData(flowSetRecord)

				select {
		        case <-dataBufferFull:

		        	for _, client := range rpcClients {
		        		var reply bool
		        		callResult := client.Go("Processor.ProcessData", structure.ProcessingFuncArgs{FlowSetHeaderStruct: flowSetHeader, DataBuffer: dataBuffer}, &reply, tempRes)
		        		
		        		if callResult.Error != nil {
		        			startProcessors()
		        		}
		        	}
		            
		        case <-optionDataBufferFull:
		            
		            //skryf data
		        }
			}
		}
	}
}
