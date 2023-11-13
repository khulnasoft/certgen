// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Khulnasoft

package main

import (
	"fmt"
	"os"

	"github.com/khulnasoft/certgen/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
