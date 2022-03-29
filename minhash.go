package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/dgryski/go-metro"
	"github.com/dgryski/go-minhash"
	"github.com/dgryski/go-spooky"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

type sliceArg []string

func (a *sliceArg) String() string {
	out := ""
	for _, arg := range *a {
		out += fmt.Sprintf("%q", arg)
		out += " "
	}
	return out
}

func (a *sliceArg) Set(value string) error {
	*a = append(*a, value)
	return nil
}

func mhash(b []byte) uint64 { 
	return metro.Hash64(b, 0) 
}

func writeSignature(sig []uint64) {
	bs, err := json.Marshal(sig)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(bs))
}

func readSignature(fname string) []uint64 {
	bs, err := ioutil.ReadFile(fname)
	if err != nil {
		log.Fatal(err)
	}

	s := []uint64{}
	err = json.Unmarshal(bs, &s)
	if err != nil {
		log.Fatal(err)
	}

	return s
}

func main() {
	n := flag.Int("n", 100, "number of minhashes to use")
	i := flag.String("i", "", "input file (default stdin)")
	flagCompares := &sliceArg{}
	flag.Var(
		flagCompares, "c", "signature files to compare (-c s1.json -c s2.json ...)")

	flag.Parse()

	if len(*flagCompares) > 1 {
		compares := *flagCompares
		for c1 := range compares {
			fname1 := compares[c1]
			s1 := readSignature(fname1)
			m1 := minhash.NewMinWiseFromSignatures(spooky.Hash64, mhash, s1)
			for c2 := c1+1; c2 < len(compares); c2++ {
				fname2 := compares[c2]
				s2 := readSignature(fname2)
				m2 := minhash.NewMinWiseFromSignatures(spooky.Hash64, mhash, s2)

				fmt.Printf("%s:%s %f\n", fname1, fname2, m1.Similarity(m2))
			}
		}

		return
	}

	m := minhash.NewMinWise(spooky.Hash64, mhash, *n)

	var reader *bufio.Reader
	if (len(*i) > 0) {
		f, err := os.Open(*i)
		if err != nil {
			log.Fatal(err)
		}

		reader = bufio.NewReader(f)
	} else {
		reader = bufio.NewReader(os.Stdin)
	}

	for {
		ln, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatal(err)
		}
		
		ln = strings.Trim(ln, "\t \n")
		if len(ln) == 0 {
			continue
		}

		m.Push([]byte(ln))
	}

	writeSignature(m.Signature())
}