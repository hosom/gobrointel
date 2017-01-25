
package brointel

import (
    "log"
    "strings"
)

type IndicatorType int

const (
    ADDR IndicatorType = iota
    URL
    SOFTWARE
    EMAIL
    DOMAIN
    USER_NAME
    FILE_HASH
    FILE_NAME
    CERT_HASH
    PUBKEY_HASH
)

// String is used to cast an IndicatorType to a bro IndicatorType
// this should prevent invalid input into the Bro Intel framework
func (i IndicatorType) String() string {
    switch i {
    case ADDR:
        return "Intel::ADDR"
    case URL:
        return "Intel::URL"
    case SOFTWARE:
        return "Intel::SOFTWARE"
    case EMAIL:
        return "Intel::EMAIL"
    case DOMAIN:
        return "Intel::DOMAIN"
    case USER_NAME:
        return "Intel::USER_NAME"
    case FILE_HASH:
        return "Intel::FILE_HASH"
    case FILE_NAME:
        return "Intel::FILE_NAME"
    case CERT_HASH:
        return "Intel::CERT_HASH"
    case PUBKEY_HASH:
        return "Intel::PUBKEY_HASH"
    }

    log.Fatal("Encountered invalid IndicatorType")
    return "None"
}

type MetaData struct {
    // An arbirary string value representing the data source
    Source              string
    // Freeform description of the data
    Desc                string
    // A URL for more information about the data
    Url                 string
    // Boolean value to allow the data itself to represent if the
    // indicator that this metadata is attached to is notice worthy 
    DoNotice            bool
}

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

    fields := []string{i.Indicator, i.Type.String(), i.Meta.Source, i.Meta.Url, DoNotice}
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
