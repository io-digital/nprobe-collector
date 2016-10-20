package main

import (
	"log"
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"os"
	"fmt"
	"net"
	"net/rpc"
	"strconv"
	"io/ioutil"
	"encoding/json"
	"github.com/io-digital/nprobe-collector/structure"
	"github.com/io-digital/nprobe-collector/function"
)

type Processor int

type DataUsage struct {
	Total uint32
	IpAddresses map[string]uint32
}

type Configuration struct {
    DbUser string
    DbPassword string
    DbName string
    DbHost string
}

var (
	ap3kDbPtr *sql.DB
	dataUsage = DataUsage{Total:0, IpAddresses: make(map[string]uint32, 0)}
	weChatIpAddresses []*net.IPNet
)

func getAp3kDB() (*sql.DB) {

	if ap3kDbPtr == nil {

		fmt.Println("Opening AP3K Database")

		configValues, err := ioutil.ReadFile("config/ap3k_db_conf.json")

		if err != nil {
	        fmt.Println("error:", err)
	    }
		configuration := Configuration{}

		err = json.Unmarshal(configValues, &configuration)
	    if err != nil {
	        fmt.Println("error:", err)
	    }

	    connectionStr := configuration.DbUser+":"+configuration.DbPassword+"@/"+configuration.DbName+"?loc=Africa%2FJohannesburg"
		ap3kDb, err := sql.Open("mysql", connectionStr)

		if err != nil {
		    log.Fatalf("nProbe DB Error: %s", err)
		}

		ap3kDbPtr = ap3kDb
	}

	if err := ap3kDbPtr.Ping(); err != nil {
	  	log.Fatalf("nProbe DB Error: %s", err)
	}

	return ap3kDbPtr
}

func init(){

	domains, err := ioutil.ReadFile("processor/ap3k/wechat_ip_domain.json")

	if err != nil {
		fmt.Println("error:", err)
	}

	var ipRangesDomains map[string][]string
	json.Unmarshal(domains, &ipRangesDomains)

	i := 0

	for i < len(ipRangesDomains["ipAddresses"]) {
		_, weChatIpAddress, _ := net.ParseCIDR(ipRangesDomains["ipAddresses"][i])
		weChatIpAddresses = append(weChatIpAddresses, weChatIpAddress)
		i++
    }

    j := 0

	for j < len(ipRangesDomains["domains"]) {
		ipStrings, _ := net.LookupHost(ipRangesDomains["domains"][j])
		
		for k := 0; k < len(ipStrings); k ++ {
			_, weChatIpAddress, err := net.ParseCIDR(ipStrings[k]+"/32")

			if err != nil {
				fmt.Println("error:", err)
			}

			weChatIpAddresses = append(weChatIpAddresses, weChatIpAddress)
		}
		
		j++
    }

    fmt.Printf("AP3K Traffic Data Processor initialised: %d IP ranges loaded, %d domains loaded \n", i, j)
}

func (p *Processor) ProcessData(processorArgs structure.ProcessingFuncArgs, ack *bool) error {

	var userIp string

	for _, packet := range processorArgs.DataBuffer {

		IPV4_SRC_ADDR, srcPresent := packet["IPV4_SRC_ADDR"]
		IPV4_DST_ADDR, dstPresent := packet["IPV4_DST_ADDR"]
		IN_DST_MAC, inSrcMacPresent := packet["IN_DST_MAC"]
		OUT_SRC_MAC, outDstMacPresent := packet["OUT_SRC_MAC"]
		
		if !srcPresent || !dstPresent || !inSrcMacPresent || !outDstMacPresent{
			continue;
		}

		srcAddr := net.IPv4(IPV4_SRC_ADDR[0], IPV4_SRC_ADDR[1], IPV4_SRC_ADDR[2], IPV4_SRC_ADDR[3])
		dstAddr := net.IPv4(IPV4_DST_ADDR[0], IPV4_DST_ADDR[1], IPV4_DST_ADDR[2], IPV4_DST_ADDR[3])

		if false {
			inDstMacAddr := strconv.FormatInt(int64(IN_DST_MAC[0]), 16) + ":" + strconv.FormatInt(int64(IN_DST_MAC[1]), 16) + ":" + strconv.FormatInt(int64(IN_DST_MAC[2]), 16) + ":" + strconv.FormatInt(int64(IN_DST_MAC[3]), 16) + ":" + strconv.FormatInt(int64(IN_DST_MAC[4]), 16) + ":" + strconv.FormatInt(int64(IN_DST_MAC[5]), 16)
			outSrcMacAddr := strconv.FormatInt(int64(OUT_SRC_MAC[0]), 16) + ":" + strconv.FormatInt(int64(OUT_SRC_MAC[1]), 16) + ":" + strconv.FormatInt(int64(OUT_SRC_MAC[2]), 16) + ":" + strconv.FormatInt(int64(OUT_SRC_MAC[3]), 16) + ":" + strconv.FormatInt(int64(OUT_SRC_MAC[4]), 16) + ":" + strconv.FormatInt(int64(OUT_SRC_MAC[5]), 16)
			fmt.Println("srcAddr: ", srcAddr)
			fmt.Println("dstAddr: ", dstAddr)
			fmt.Println("inDstMacAddr: ", inDstMacAddr)
			fmt.Println("outSrcMacAddr: ", outSrcMacAddr)
		}

		for _, ipNet := range weChatIpAddresses {


			if ipNet.Contains(srcAddr) {
				userIp = dstAddr.String()
			} else if ipNet.Contains(dstAddr) {
				userIp = srcAddr.String()
			} else {
				continue;
			}

			_, ipAddressFound := dataUsage.IpAddresses[userIp]

			if !ipAddressFound {
				dataUsage.IpAddresses[userIp] = 0
			}

			dataUsage.IpAddresses[userIp] += function.ReadUint32(packet["IN_BYTES"]) + function.ReadUint32(packet["OUT_BYTES"])
			dataUsage.Total += function.ReadUint32(packet["IN_BYTES"]) + function.ReadUint32(packet["OUT_BYTES"])

			jsonRaw, err := json.Marshal(dataUsage)
			if err != nil {
				fmt.Println("error:", err)
			}

			err = ioutil.WriteFile("/var/www/html/ap3k_wechat_usage.json", jsonRaw, os.FileMode(0777))
			if err != nil {
				fmt.Println("error:", err)
			}
		}
	}

	*ack = true
	return nil
}

func main() {
	addr, err := net.ResolveTCPAddr("tcp", "0.0.0.0:42587")
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
