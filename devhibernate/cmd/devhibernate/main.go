package main

import (
	"github.com/vtino17/devhibernate/internal/cli"
	"os"
)

var version = "dev"

func main() { os.Exit(cli.Run(os.Args[1:], version, os.Stdout, os.Stderr)) }
