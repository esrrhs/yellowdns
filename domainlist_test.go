package main

import (
	"testing"
	"time"

	"github.com/esrrhs/gohome/thirdparty"
	"github.com/oschwald/maxminddb-golang"
)

func TestClassifyEmbedded(t *testing.T) {
	if _, _, err := loadDomainLists("", ""); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		want int
	}{
		{"www.baidu.com.", routeLocal},
		{"QQ.com", routeLocal},
		{"a1.mzstatic.com.", routeLocal},
		{"adservice.google.com.", routeLocal},
		{"www.google.com.", routeExtern},
		{"github.com.", routeExtern},
		{"example.cn.", routeLocal},
		{"www.example.中国.", routeLocal},
		{"example.com.", routeAuto},
	}
	for _, c := range cases {
		if got := classifyName(c.name); got != c.want {
			t.Errorf("%s got %s want %s", c.name, routeName(got), routeName(c.want))
		}
	}
}

func TestClassifySpecificChinaWins(t *testing.T) {
	chinaDomains = domainSet{}
	gfwDomains = domainSet{}
	addDomain(gfwDomains, "google.com")
	addDomain(chinaDomains, "adservice.google.com")
	if got := classifyName("adservice.google.com."); got != routeLocal {
		t.Fatalf("specific china domain got %s", routeName(got))
	}
	if got := classifyName("www.google.com."); got != routeExtern {
		t.Fatalf("parent gfw domain got %s", routeName(got))
	}
	if _, _, err := loadDomainLists("", ""); err != nil {
		t.Fatal(err)
	}
}

func TestCountryDB(t *testing.T) {
	db, err := maxminddb.Open("GeoLite2-Country.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if int64(db.Metadata.BuildEpoch) < time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC).Unix() {
		t.Fatalf("country db too old: %s", time.Unix(int64(db.Metadata.BuildEpoch), 0).UTC())
	}
	if err := thirdparty.LoadGeoip2("GeoLite2-Country.mmdb"); err != nil {
		t.Fatal(err)
	}
	cn, err := thirdparty.GetGeoipCountryIsoCode("114.114.114.114")
	if err != nil || cn != "CN" {
		t.Fatalf("114.114.114.114 %q %v", cn, err)
	}
	us, err := thirdparty.GetGeoipCountryIsoCode("8.8.8.8")
	if err != nil || us != "US" {
		t.Fatalf("8.8.8.8 %q %v", us, err)
	}
}
