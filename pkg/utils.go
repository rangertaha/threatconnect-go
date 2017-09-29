package threatconnect

import (
	"net/http"
	"io/ioutil"
	"fmt"

	log "github.com/Sirupsen/logrus"
	"encoding/json"
	"bytes"
)

func CheckResponse(res *http.Response, err error) error {


    if err != nil {
        log.Fatalf("ERROR: %s", err)
    }

    body, err := ioutil.ReadAll(res.Body)
    if err != nil {
        log.Fatalf("ERROR: %s", err)
    }

    fmt.Printf("%s", body)

	return err
}


func PrettyPrintJson(data json.RawMessage) {
	var prettyJSON bytes.Buffer

	err := json.Indent(&prettyJSON, data, "", "\t")
	if err != nil {
		log.Warn("Pretty print JSON parse error: ", err)
	}
	if log.GetLevel() == log.DebugLevel {
		fmt.Println(string(prettyJSON.Bytes()))
	}
}