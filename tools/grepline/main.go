package main

// grepline prints lines of a file whose index falls in a range, or lines matching
// a substring, so that a huge source file can be inspected in small chunks
// without loading it whole into context.
//
//	go run ./tools/grepline <file> <startLine> <count>            # dump a line range
//	go run ./tools/grepline <file> -m <substring> <contextLines>   # grep-like
import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: grepline file [start count | -m substr [ctx]]")
		os.Exit(2)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if len(os.Args) >= 3 && os.Args[2] == "-m" {
		sub := os.Args[3]
		ctx := 0
		if len(os.Args) > 4 {
			ctx, _ = strconv.Atoi(os.Args[4])
		}
		for i, l := range lines {
			if !strings.Contains(l, sub) {
				continue
			}
			lo := i - ctx
			if lo < 0 {
				lo = 0
			}
			hi := i + ctx
			if hi >= len(lines) {
				hi = len(lines) - 1
			}
			fmt.Printf("--- line %d ---\n", i+1)
			for j := lo; j <= hi; j++ {
				fmt.Printf("%6d  %s\n", j+1, lines[j])
			}
		}
		return
	}
	start, _ := strconv.Atoi(os.Args[2])
	count, _ := strconv.Atoi(os.Args[3])
	if count <= 0 {
		count = 40
	}
	for i := start - 1; i < start-1+count && i < len(lines); i++ {
		if i < 0 {
			continue
		}
		fmt.Printf("%6d  %s\n", i+1, lines[i])
	}
}
