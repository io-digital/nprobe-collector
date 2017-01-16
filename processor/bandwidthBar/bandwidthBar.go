package main

import (
	"log"
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"fmt"
	"time"
	"github.com/jinzhu/now"
	"net"
	"net/rpc"
	"strings"
	"github.com/io-digital/nprobe-collector/structure"
	"github.com/io-digital/nprobe-collector/function"
)

type Processor int

var nProbeDbPtr *sql.DB
var bBarDbPtr *sql.DB
var connectedIpUsernames map[string]string
var ipRangeServiceIds map[string]int
var blacklist []string

func inBlacklist(ipAddress string) bool {
    for _, b := range blacklist {
        if b == ipAddress {
            return true
        }
    }
    return false
}

func getNProbeDB() (*sql.DB) {

	if nProbeDbPtr == nil {

		fmt.Println("Opening nProbe DB")

		configuration := function.GetDbConfig("nprobe_db_conf.json")

	    connectionStr := configuration.DbUser+":"+configuration.DbPassword+"@/"+configuration.DbName+"?loc=Africa%2FJohannesburg"
		nProbeDb, err := sql.Open("mysql", connectionStr)

		if err != nil {
		    log.Fatalf("nProbe DB Error: %s", err)
		}

		nProbeDbPtr = nProbeDb
	}

	if err := nProbeDbPtr.Ping(); err != nil {
	  	log.Fatalf("nProbe DB Error: %s", err)
	}

	return nProbeDbPtr
}

func getBBarDB() (*sql.DB) {

	if bBarDbPtr == nil {

		fmt.Println("Opening BBAR DB")
		configuration := function.GetDbConfig("bbar_db_conf.json")

		connectionStr := configuration.DbUser+":"+configuration.DbPassword+"@tcp("+configuration.DbHost+":3306)/"+configuration.DbName
		bbarDb, err := sql.Open("mysql", connectionStr)

		if err != nil {
		    log.Fatal(err)
		}

		bBarDbPtr = bbarDb
	}

	if err := bBarDbPtr.Ping(); err != nil {
	  	log.Fatal(err)
	}

	return bBarDbPtr
}

func getIpAddressUsernameMap() map[string]string {

	blacklist = nil
	returnMap := make(map[string]string)
	var UserName string
	var FramedIPAddress string

	bbardb := getBBarDB()
		
	rows, err := bbardb.Query("SELECT UserName, FramedIPAddress FROM radacct WHERE AcctStopTime IS NULL")

	if err != nil {
	    log.Fatal(err)
	}

	for rows.Next() {

		if err := rows.Scan(&UserName, &FramedIPAddress); err != nil {
	        log.Fatal(err)
	    }else if strings.Trim(FramedIPAddress, " ") != "" && strings.Trim(UserName, " ") != "" {
	    	returnMap[FramedIPAddress] = UserName
	    }
	}

	fmt.Println("Users connected: ", len(returnMap))

	return returnMap
}

func getUserName(ipAddress string) (string, error) {

	bbardb := getBBarDB()

	var userName string
	row := bbardb.QueryRow("SELECT UserName FROM radacct WHERE AcctStopTime IS NULL AND FramedIPAddress = ?", ipAddress)

	err := row.Scan(&userName)

	return userName, err
}

func getIpAddressServiceIdMap() map[string]int {

	returnMap := make(map[string]int)
	var serviceId int
	var ipAddresses string

	bbardb := getBBarDB()
		
	rows, err := bbardb.Query("SELECT id as service_id, ip_addresses FROM bandwidth_services WHERE ip_addresses IS NOT NULL")

	if err != nil {
	    log.Fatal(err)
	}

	for rows.Next() {

		if err := rows.Scan(&serviceId, &ipAddresses); err != nil {
	        log.Fatal(err)
	    }

	    ipAddressSlice := strings.Split(ipAddresses, ";")

	    for _, ipAddress := range ipAddressSlice {

	    	if ipAddress == ""{
	    		continue;
	    	} 

	    	if !strings.Contains(string(ipAddress), "/") {
	    		ipAddress += "/32"
	    	}
	    	returnMap[string(ipAddress)] = serviceId
	    }
	}

	return returnMap
}

func init(){

	getBBarDB()
	getNProbeDB()

	go func() {
		t := time.NewTicker(time.Minute)
		for {
		    connectedIpUsernames = getIpAddressUsernameMap()
		    ipRangeServiceIds = getIpAddressServiceIdMap()
		    <-t.C
		}
	}()
}

func (p *Processor) Test(line []byte, ack *bool) error {
	fmt.Println(string(line))
	return nil
}

func (p *Processor) ProcessData(processorArgs structure.ProcessingFuncArgs, ack *bool) error {

	nprobeDB := getNProbeDB()

	var userIp string
	timeStamp := now.New(processorArgs.FlowSetHeaderStruct.Timestamp)
	hourStart := timeStamp.BeginningOfHour()
	monthStart := timeStamp.BeginningOfMonth()
	now := time.Now()

	tx, _ := nprobeDB.Begin()
	stmt, _ := tx.Prepare("INSERT INTO username_service_usage (username, bytes, service_id, hour_start, month_start, updated_at) VALUES (?,?,?,?,?,?) ON DUPLICATE KEY UPDATE bytes = bytes + ?, updated_at = ?")

	for _, packet := range processorArgs.DataBuffer {

		userIp = ""

		IPV4_SRC_ADDR, srcPresent := packet["IPV4_SRC_ADDR"]
		IPV4_DST_ADDR, dstPresent := packet["IPV4_DST_ADDR"]
		
		if !srcPresent || !dstPresent {
			continue
		}

		srcAddr := net.IPv4(IPV4_SRC_ADDR[0], IPV4_SRC_ADDR[1], IPV4_SRC_ADDR[2], IPV4_SRC_ADDR[3])
		dstAddr := net.IPv4(IPV4_DST_ADDR[0], IPV4_DST_ADDR[1], IPV4_DST_ADDR[2], IPV4_DST_ADDR[3])

		for ipRange, serviceId := range ipRangeServiceIds {

			_, ipnet, err := net.ParseCIDR(ipRange)

			if err != nil{
				fmt.Println("Error: ", err)
				continue
			}

			if ipnet.Contains(srcAddr) {
				userIp = dstAddr.String()
			} else if ipnet.Contains(dstAddr) {
				userIp = srcAddr.String()
			}

			if userIp == "" || inBlacklist(userIp) {
				continue
			}

			userName, found := connectedIpUsernames[userIp]

			if !found {

				userName, err := getUserName(userIp)

				if err == nil {
					found = true
					connectedIpUsernames[userIp] = userName
				}else{
					blacklist = append(blacklist, userIp)
				}
			}

			if found {
				bytesTotal := function.ReadUint32(packet["IN_BYTES"]) + function.ReadUint32(packet["OUT_BYTES"])
				stmt.Exec(userName, bytesTotal, serviceId, hourStart, monthStart, now, bytesTotal, now)
			}

			break			
		}
	}

	tx.Commit()
	*ack = true
	return nil
}

func main(){

	processorConfig := function.GetProcessorConfig("../../config/processor.json")

	addr, err := net.ResolveTCPAddr("tcp", "0.0.0.0:"+processorConfig.ServerPort)
	if err != nil {
		log.Fatal(err)
	}

	inbound, err := net.ListenTCP("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}

	processor := new(Processor)
	rpc.Register(processor)
	rpc.Accept(inbound)
}

