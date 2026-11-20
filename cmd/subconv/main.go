// Command subconv converts a subscription file and prints the mihomo config fragment.
//
//	subconv [-json] <file | ->
//
// Warnings go to standard error, one per line as "code: detail". It is a tool for trying
// subscriptions and scripting; clients link the package instead.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/openweir/subconv"
)

func main() {
	asJSON := flag.Bool("json", false, "print the whole result as JSON, warnings included")
	flag.Usage = func() {
		fmt.Fprintln(flag.CommandLine.Output(), "usage: subconv [-json] <file | ->")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(flag.Arg(0), *asJSON, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "subconv:", err)
		os.Exit(1)
	}
}

func run(name string, asJSON bool, stdout, stderr io.Writer) error {
	var data []byte
	var err error
	if name == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(name)
	}
	if err != nil {
		return err
	}
	result, err := subconv.Convert(data)
	if err != nil {
		return err
	}
	if asJSON {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		return encoder.Encode(result)
	}
	fragment, err := result.YAML()
	if err != nil {
		return err
	}
	if _, err := stdout.Write(fragment); err != nil {
		return err
	}
	for _, warning := range result.Warnings {
		fmt.Fprintf(stderr, "%s: %s\n", warning.Code, warning.Detail)
	}
	return nil
}
