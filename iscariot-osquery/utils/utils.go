package utils

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"runtime"
	"strings"
)

var saBOFs = []string{
	"adcs_enum",
	"adcs_enum_com",
	"adcs_enum_com2",
	"adv_audit_policies",
	"arp",
	"cacls",
	"dir",
	"driversigs",
	"enum_filter_driver",
	"enumlocalsessions",
	"env",
	"findLoadedModule",
	"get-netsession",
	"get_password_policy",
	"ipconfig",
	"ldapsearch",
	"listdns",
	"listmods",
	"netgroup",
	"netlocalgroup",
	"netshares",
	"netstat",
	"netuse",
	"netuser",
	"netuserenum",
	"netview",
	"nonpagedldapsearch",
	"nslookup",
	"reg_query",
	"resources",
	"routeprint",
	"sc_enum",
	"sc_qc",
	"sc_qdescription",
	"sc_qfailure",
	"sc_qtriggerinfo",
	"sc_query",
	"schtasksenum",
	"schtasksquery",
	"tasklist",
	"uptime",
	"vssenum",
	"whoami",
	"windowlist",
	"wmi_query",
}

// Update with `curl https://api.github.com/users/sliverarmory/repos | jq '.[] | select(.language == "C#").name'`
// Or browse to https://github.com/orgs/sliverarmory/repositories?q=&type=all&language=c%23&sort=name
var armoryAssemblies = []string{
	"Certify",
	"KrbRelayUp",
	"nopowershell",
	"Rubeus",
	"Seatbelt",
	"Sharp-SMBExec",
	"SharPersist",
	"SharpHound",
	"SharpHound3",
	"SharpMapExec",
	"SharpSecDump",
	"SharpUp",
	"SharpWMI",
}

func Contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func UntarFileFromURL(url string, fileName string) (content []byte, err error) {
	tarFile, err := downloadFile(url)
	if err != nil {
		return nil, err
	}
	reader := bytes.NewReader(tarFile)
	gzr, err := gzip.NewReader(reader)
	if err != nil {
		return nil, err
	}
	defer gzr.Close()

	tarReader := tar.NewReader(gzr)

	for {
		header, err := tarReader.Next()

		switch {
		// if no more files are found return
		case err == io.EOF:
			return nil, errors.New("tar file does not contain: " + fileName)

		// return any other error
		case err != nil:
			return nil, err

		// if the header is nil, just skip it (not sure how this happens)
		case header == nil:
			continue
		}

		// the following switch could also be done using fi.Mode(), not sure if there
		// a benefit of using one vs. the other.
		// fi := header.FileInfo()

		// check the file type
		switch header.Typeflag {

		// if its a dir skip it
		case tar.TypeDir:
			continue

		// if it's a file check if its the one we want
		case tar.TypeReg:
			if header.Name == "./"+fileName {
				fileContent, err := ioutil.ReadAll(tarReader)
				if err != nil {
					return nil, err
				}

				return fileContent, nil
			}
		}
	}
}

func LoadBOFFromDisk(bofName string) (content []byte, err error) {
	var archEnding string
	if runtime.GOARCH == "amd64" {
		archEnding = ".x64.o"
	} else {
		archEnding = ".x86.o"
	}
	fileContent, err := ioutil.ReadFile(bofName + archEnding)
	if err != nil {
		return nil, err
	}
	return fileContent, nil
}

func LoadFileFromDisk(fileName string) (content []byte, err error) {
	fileContent, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	return fileContent, nil
}

func GetSABOF(bofName string) (content []byte, err error) {
	url, err := createURLForSABOF(bofName)
	if err != nil {
		return nil, err
	}
	fileContent, err := downloadFile(url)
	if err != nil {
		return nil, err
	}
	return fileContent, nil
}

func downloadFile(url string) (content []byte, err error) {
	var fileContent []byte

	client := &http.Client{}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalln(err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36 Edg/105.0.1343.42")

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}

	// Writer the body to memory
	fileContent, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return fileContent, nil
}

// Generate a URL for a SA BOF
// Example: https://github.com/trustedsec/CS-Situational-Awareness-BOF/raw/master/SA/arp/arp.x64.o
func createURLForSABOF(bofName string) (url string, err error) {

	if !Contains(saBOFs, bofName) {
		return "", errors.New("no bof of that name exists in the SA repo")
	}

	var bofArchString string
	switch runtime.GOARCH {
	case "amd64":
		bofArchString = "x64"
	case "386":
		bofArchString = "x86"
	default:
		bofArchString = "error"
	}
	if bofArchString == "error" {
		return "", errors.New("bof arch missing or unsupported: " + runtime.GOARCH)
	}

	url = fmt.Sprintf("https://github.com/trustedsec/CS-Situational-Awareness-BOF/raw/master/SA/%s/%s.%s.o",
		bofName, bofName, bofArchString)

	return url, nil
}

func GetAssembly(assemblyName string) (content []byte, err error) {
	if !Contains(armoryAssemblies, assemblyName) {
		return nil, errors.New("no assembly of that name exists in the sliverarmory repo")
	}
	assemblyLower := strings.ToLower(assemblyName)

	url := fmt.Sprintf("https://github.com/sliverarmory/%s/releases/latest/download/%s.tar.gz",
		assemblyLower, assemblyLower)

	fileContent, err := UntarFileFromURL(url, assemblyName+".exe")
	if err != nil {
		return nil, err
	}

	return fileContent, nil
}
