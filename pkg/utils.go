package threatconnect

import (
	"net/http"
	"io/ioutil"
	"fmt"

	log "github.com/Sirupsen/logrus"
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
