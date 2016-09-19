package structure

import (
	"time"
)

type FlowSetHeader struct {
	Version uint16
	Records uint16
	SystemUptime uint32
	Timestamp time.Time
}

type FlowSetRecord struct {
	Id uint16
	Length uint16
	Data []byte
}

var NetFlowFieldTypes = map[uint16]string{
	1 : "IN_BYTES",
	2 : "IN_PKTS",
	3 : "FLOWS",
	4 : "PROTOCOL",
	5 : "SRC_TOS",
	6 : "TCP_FLAGS",
	7 : "L4_SRC_PORT",
	8 : "IPV4_SRC_ADDR",
	9 : "SRC_MASK",
	10: "INPUT_SNMP",
	11 : "L4_DST_PORT",
	12 : "IPV4_DST_ADDR",
	13 : "DST_MASK",
	14 : "OUTPUT_SNMP",
	15 : "IPV4_NEXT_HOP",
	16 : "SRC_AS",
	17 : "DST_AS",
	18 : "BGP_IPV4_NEXT_HOP",
	19 : "MUL_DST_PKTS",
	20 : "MUL_DST_BYTES",
	21 : "LAST_SWITCHED",
	22 : "FIRST_SWITCHED",
	23 : "OUT_BYTES",
	24 : "OUT_PKTS",
	25 : "MIN_PKT_LNGTH",
	26 : "MAX_PKT_LNGTH",
	27 : "IPV6_SRC_ADDR",
	28 : "IPV6_DST_ADDR",
	29 : "IPV6_SRC_MASK",
	30 : "IPV6_DST_MASK",
	31 : "IPV6_FLOW_LABEL",
	32 : "ICMP_TYPE",
	41 : "TOTAL_PKTS_EXP",
	42 : "TOTAL_FLOWS_EXP",
	80 : "IN_DST_MAC",
	81 : "OUT_SRC_MAC",
	82 : "IF_NAME",
	83 : "IF_DESC",
	84 : "SAMPLER_NAME",
	85 : "IN_PERMANENT_BYTES",
	86 : "IN_PERMANENT PKTS",

}

var NetFlowScopeFields = map[uint16]string{
	1 : "System",
	2 : "Interface",
	3 : "Line Card",
	4 : "NetFlow Cache",
	5 : "Template",
}