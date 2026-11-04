package main

import (
	"fmt"
	"log"
	"os"
	"text/tabwriter"

	"github.com/alecthomas/kong"
	"github.com/jdelkins/pia-tools/internal/pia"
)

type CLI struct {
	PF    bool `name:"pf" short:"f" xor:"pf" help:"Only list regions that support port forwarding."`
	NoPF  bool `name:"no-pf" short:"F" xor:"pf" help:"Only list regions that don't support port forwarding."`
	Geo   bool `name:"geo" short:"g" xor:"geo" help:"Only list geolocated regions."`
	NoGeo bool `name:"no-geo" short:"G" xor:"geo" help:"Only list regions that aren't geolocated."`
}

func main() {
	var cli CLI
	kong.Parse(&cli, kong.Name("pia-listregions"))

	regions, err := pia.RegionsWithLatency()
	if err != nil {
		log.Fatalf("%v", err)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", "ID",             "NAME",                    "LATENCY",   "GEO?", "PF?")
	fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", "==============", "=======================", "=========", "====", "===")
	for i := range regions {
		r := &regions[i]
		if cli.PF && !r.PortForward || cli.NoPF && r.PortForward || cli.Geo && !r.Geo || cli.NoGeo && r.Geo {
			continue
		}
		geo := ""
		if r.Geo {
			geo = "  ✓"
		}
		pf := ""
		if r.PortForward {
			pf = " ✓"
		}
		if r.Latency == 0 {
			fmt.Fprintf(w, "%s\t%s\tN/A\t%s\t%s\n", r.Id, r.Name, geo, pf)
		} else {
			fmt.Fprintf(w, "%s\t%s\t%d ms\t%s\t%s\n", r.Id, r.Name, r.Latency.Milliseconds(), geo, pf)
		}
	}
	w.Flush()
}
