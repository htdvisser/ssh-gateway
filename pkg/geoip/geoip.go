package geoip

import (
	"errors"
	"fmt"
	"net"

	"github.com/oschwald/geoip2-golang"
)

type DB struct {
	*geoip2.Reader
}

var (
	ErrInvalidIP = errors.New("invalid IP address")
	ErrNotFound  = errors.New("no location found for IP address")
)

func (db *DB) City(ipStr string) (string, error) {
	if db == nil {
		return "", nil
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", ErrInvalidIP
	}
	record, err := db.Reader.City(ip)
	if err != nil {
		return "", err
	}
	if record.City.GeoNameID == 0 {
		return "", ErrNotFound
	}
	return fmt.Sprintf("%s, %s", record.City.Names["en"], record.Country.Names["en"]), nil
}

func Open(f string) (*DB, error) {
	r, err := geoip2.Open(f)
	if err != nil {
		return nil, err
	}
	return &DB{Reader: r}, nil
}
