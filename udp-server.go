package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"math"
	"time"
	"strconv"
	"github.com/io-digital/nprobe-collector/structure"
	"github.com/io-digital/nprobe-collector/function"
	"github.com/io-digital/nprobe-collector/processor/ap3k"
)

var (
	debugMode bool
	port string

	dataTemplates = make(map[uint16]map[string][]uint16)
	optionTemplates = make(map[uint16]map[string][]uint16)
	packetCount = 0

	udpBufferChan = make(chan []byte)
	flowSetRecordChan = make(chan structure.FlowSetRecord)
	dataBufferChan = make(chan []map[string][]byte)
	templateNotFoundChan = make(chan int)

	flowSetHeaderReadDone = make(chan bool)
	flowSetRecordReadDone = make(chan bool)
	optionDataBufferFull = make(chan bool)
)

func readFlowSetHeader(udpBuffer []byte, flowSetHeaderStruct *structure.FlowSetHeader) {

	flowSetHeader := udpBuffer[0:20]

	flowSetHeaderStruct.Version = function.ReadUint16(flowSetHeader[0:2])
	flowSetHeaderStruct.Records = function.ReadUint16(flowSetHeader[2:4])
	flowSetHeaderStruct.SystemUptime = function.ReadUint32(flowSetHeader[4:8])
	flowSetHeaderStruct.Timestamp =  time.Unix(int64(function.ReadUint32(flowSetHeader[8:12])), 0)

	if debugMode {
		fmt.Printf("FlowSet Header: NetFlow Version = %d, Number of Packets = %d, Time = %s \n", flowSetHeaderStruct.Version, flowSetHeaderStruct.Records, flowSetHeaderStruct.Timestamp)
	}

	packetCount++

	if(math.Remainder(float64(packetCount), 1000) == 0){
		fmt.Printf("Records processed: %d\n", packetCount)
	}

	udpBufferChan <- udpBuffer[20:]
}

func readFlowSetRecord(udpBuffer []byte) {
	flowSetIdLength := udpBuffer[0:4]
	flowSetRecord := structure.FlowSetRecord{Id: function.ReadUint16(flowSetIdLength[0:2]),Length: function.ReadUint16(flowSetIdLength[2:4]), Data: udpBuffer[4:]}
	flowSetRecordChan <- flowSetRecord
}

func parseFlowSetTemplate(flowSetRecord structure.FlowSetRecord) {

	readToCollectData := false

	if len(dataTemplates) == 0 {
		readToCollectData = true
		fmt.Println("NetFlow Templates found, loading...")
	}

	templates :=  flowSetRecord.Data

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

		_, templateExists := dataTemplates[templateId]

		if !templateExists {
			fmt.Println("Loaded Template ID: ", templateId)
		}

		dataTemplates[templateId] = map[string][]uint16{
			"fieldTypeIndex": fieldTypeIndex,
			"fieldLength":    fieldLength,
		}
	}

	if readToCollectData {
		fmt.Println("Now collecting data")
	}
}

func parseFlowSetOptions(flowSetRecord structure.FlowSetRecord) {

	template := flowSetRecord.Data
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

func parseFlowSetData(flowSetRecord structure.FlowSetRecord) {

	flowSetData := flowSetRecord.Data
	templateId := flowSetRecord.Id

	dataTemplate, dataTemplateExists := dataTemplates[templateId]
	optionTemplate, optionTemplateExists := optionTemplates[templateId]

	if dataTemplateExists {

		if debugMode {
			fmt.Printf("Parsing FlowSet Data: TemplateId = %d, Packet Length = %d\n", templateId, len(flowSetData))
			fmt.Println("------------------------------------------------------------------------")
		}

		fieldValues := flowSetData 

		dataBuffer := make([]map[string][]byte, 0)

		for len(fieldValues) >= 4 {

			packet := make(map[string][]byte, 0)

			for index, fieldLength := range dataTemplate["fieldLength"] {

				fieldMapIndex := dataTemplate["fieldTypeIndex"][index]
				fieldName := structure.NetFlowFieldTypes[fieldMapIndex]

				if fieldName == "" {
					fieldName = strconv.Itoa(int(fieldMapIndex))
				}

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

		dataBufferChan <- dataBuffer

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

		templateNotFoundChan <- int(templateId)
	}
}

func processFlowSetData(flowSetHeaderStruct structure.FlowSetHeader, fullBuffer []map[string][]byte) {
	processor.ProcessData(flowSetHeaderStruct, fullBuffer)
}


func main() {

	debugPtr := flag.Bool("debug", false, "Outputs data as it is received")
	portPtr := flag.String("port", "2055", "The port that the server listens on")
	flag.Parse()

	debugMode = *debugPtr
	port = *portPtr

	fmt.Println("Launching UDP server...")
	udpAddr, err := net.ResolveUDPAddr("udp4", ":"+port)

	if err != nil {
         log.Fatal(err)
 	}

 	reader, err := net.ListenUDP("udp4", udpAddr)
	reader.SetReadBuffer(1048576)

	if err != nil {
		log.Fatalf("UDP Error: %s", err)
	}

	fmt.Println("UDP server up and listening on port 2055")
    defer reader.Close()

	processor.Initialize()

	fmt.Println("Waiting for NetFlow Template(s)...")

	flowSetHeader := structure.FlowSetHeader{}

	for {

		udpBuffer := make([]byte, 1048576)
		n, _, err := reader.ReadFromUDP(udpBuffer)

		if err != nil {
        	log.Fatal(err)
 		}
		
		udpBuffer = udpBuffer[0:n]

		if debugMode {
        	fmt.Println("UDP Read Length: ", len(udpBuffer))
        }

		go readFlowSetHeader(udpBuffer, &flowSetHeader)
		udpBuffer = <-udpBufferChan

		go readFlowSetRecord(udpBuffer)
		flowSetRecord := <-flowSetRecordChan
		 
		if debugMode {
			fmt.Printf("FlowSet Record: FlowSetId = %d, Length = %d\n", flowSetRecord.Id, flowSetRecord.Length)
		}

		switch flowSetRecord.Id {

		case 0:
			parseFlowSetTemplate(flowSetRecord)
		case 1:
			parseFlowSetOptions(flowSetRecord)
		default:
			go parseFlowSetData(flowSetRecord)

			select {
	        case fullBuffer := <-dataBufferChan:

	            go processFlowSetData(flowSetHeader, fullBuffer)

	        case <-optionDataBufferFull:
	            
	            if debugMode {
	            	fmt.Println("Option Buffer full")
	            }

	        case templateId := <- templateNotFoundChan:
	        	if debugMode {
	        		fmt.Println("Template not found, ID: ", templateId)
	        	}
	        }
		}
	}
}
