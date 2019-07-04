package geoip

import (
	"errors"
	"fmt"
	"net"

	"github.com/oschwald/geoip2-golang"
)

type DB struct {
	cities *geoip2.Reader
	asns   *geoip2.Reader
}

func Open(f string) (*DB, error) {
	r, err := geoip2.Open(f)
	if err != nil {
		return nil, err
	}
	return &DB{cities: r}, nil
}

func (db *DB) AddASN(f string) error {
	r, err := geoip2.Open(f)
	if err != nil {
		return err
	}
	db.asns = r
	return nil
}

var ErrNotFound = errors.New("no location found for IP address")

func (db *DB) asn(ip net.IP) (string, error) {
	if db.asns == nil {
		return "", ErrNotFound
	}
	asn, err := db.asns.ASN(ip)
	if err != nil {
		return "", err
	}
	if asn.AutonomousSystemNumber == 0 {
		return "", ErrNotFound
	}
	return asn.AutonomousSystemOrganization, nil
}

func (db *DB) city(ip net.IP) (string, error) {
	if db.cities == nil {
		return "", ErrNotFound
	}
	record, err := db.cities.City(ip)
	if err != nil {
		return "", err
	}
	if record.Country.GeoNameID == 0 {
		return "", ErrNotFound
	}
	if record.City.GeoNameID == 0 {
		return record.Country.IsoCode, nil
	}
	return fmt.Sprintf("%s %s", record.City.Names["en"], record.Country.IsoCode), nil
}

var ErrInvalidIP = errors.New("invalid IP address")

func (db *DB) Info(ipStr string) (string, error) {
	if db == nil {
		return "", nil
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", ErrInvalidIP
	}
	asn, _ := db.asn(ip)
	city, _ := db.city(ip)
	if city == "" {
		return asn, nil
	}
	return fmt.Sprintf("%s %s", asn, city), nil
}
