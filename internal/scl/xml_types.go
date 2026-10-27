package scl

import "encoding/xml"

type SCL struct {
	XMLName       xml.Name      `xml:"SCL"`
	Communication Communication `xml:"Communication"`
	IEDs          []IED         `xml:"IED"`
}

type Communication struct {
	SubNetworks []SubNetwork `xml:"SubNetwork"`
}

type SubNetwork struct {
	ConnectedAPs []ConnectedAP `xml:"ConnectedAP"`
}

type ConnectedAP struct {
	IEDName string `xml:"iedName,attr"`
	GSEs    []GSE  `xml:"GSE"`
}

type GSE struct {
	LDInst  string  `xml:"ldInst,attr"`
	CBName  string  `xml:"cbName,attr"`
	Address Address `xml:"Address"`
}

type Address struct {
	Ps []P `xml:"P"`
}

type P struct {
	Type  string `xml:"type,attr"`
	Value string `xml:",chardata"`
}

type IED struct {
	Name        string      `xml:"name,attr"`
	AccessPoint AccessPoint `xml:"AccessPoint"`
}

type AccessPoint struct {
	Server Server `xml:"Server"`
}

type Server struct {
	LDevices []LDevice `xml:"LDevice"`
}

type LDevice struct {
	Inst string `xml:"inst,attr"`
	LN0  LN0    `xml:"LN0"`
}

type LN0 struct {
	GSEControls []GSEControl `xml:"GSEControl"`
	DataSets    []DataSet    `xml:"DataSet"`
}

type GSEControl struct {
	Name    string `xml:"name,attr"`
	DatSet  string `xml:"datSet,attr"`
	ConfRev int    `xml:"confRev,attr"`
	AppID   string `xml:"appID,attr"`
}

type DataSet struct {
	Name string `xml:"name,attr"`
	FCDA []any  `xml:"FCDA"`
}
