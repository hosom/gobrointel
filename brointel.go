
package brointel

import (
    "log"
    "strings"
)

// IndicatorType mapping for Bro intelligence framework
// see the documentation for Intel::Type within Bro for more information
type IndicatorType int

const (
	// Addr IP Address
    Addr IndicatorType = iota
	// Subnet in CIDR notation
	Subnet
	// URL without the prefix
    URL
	// Software name
    Software
	// Email address
    Email
	// Domain name
    Domain
	// User name
    Username
	// Filehash is a non-hash type specific hash
    FileHash
	// Filename is a filename from a protocol that supports defined file names
    FileName
	// CertHash is a certificate's SHA-1 hash
    CertHash
	// PubKeyHash is a public key MD5 hash
    PubKeyHash
)

// headerFields contains the fields to be combined to make up a bro intel 
// file header
var headerFields = []string{"#fields", "indicator", "indicator_type", "meta.source", "meta.desc", "meta.url", "meta.do_notice"}

// Headers returns a string containing Bro intelligence file headers
func Headers() string {
    return strings.Join(headerFields, "\t")
}

// String is used to cast an IndicatorType to a bro IndicatorType
// this should prevent invalid input into the Bro Intel framework
func (i IndicatorType) String() string {
    switch i {
    case Addr:
        return "Intel::ADDR"
	case Subnet:
		return "Intel::SUBNET"
    case URL:
        return "Intel::URL"
    case Software:
        return "Intel::SOFTWARE"
    case Email:
        return "Intel::EMAIL"
    case Domain:
        return "Intel::DOMAIN"
    case Username:
        return "Intel::USER_NAME"
    case FileHash:
        return "Intel::FILE_HASH"
    case FileName:
        return "Intel::FILE_NAME"
    case CertHash:
        return "Intel::CERT_HASH"
    case PubKeyHash:
        return "Intel::PUBKEY_HASH"
    }

    log.Fatal("Encountered invalid IndicatorType")
    return "None"
}

// MetaData contains enrichment data about an Item
type MetaData struct {
    // Source is an arbirary string value representing the data source
    Source              string
    // Freeform description of the data
    Desc                string
    // URL for more information about the data
    URL                 string
    // DoNotice is aBoolean value to allow the data itself to represent if the
    // indicator that this metadata is attached to is notice worthy 
    DoNotice            bool
}

// Item is a single piece of intelligence / observable
type Item struct {
    // The intelligence indicator
    Indicator           string
    // The type of data that the indicator field represents
    Type                IndicatorType
    // Metadata for the item. Typically represents more deeply descriptive
    // data for a piece of intelligence
    Meta                MetaData
}

// String creates a string representation of the Item. This can be used
// to build Bro intel files
func (i Item) String() string {
    DoNotice := "F"
    if i.Meta.DoNotice {
        DoNotice = "T"
    }

    fields := []string{i.Indicator, i.Type.String(), i.Meta.Source, i.Meta.Desc, i.Meta.URL, DoNotice}
    return strings.Join(fields, "\t")
}

// StringItems takes an array of Item structs and creates a line delimited 
// string to represent that group of Items
func StringItems(items []Item) string {
    var lines []string
    for _, item := range items {
        lines = append(lines, item.String())
    }

    return strings.Join(lines, "\n")
}
