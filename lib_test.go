package tinycert_test

import (
	"log"
	"testing"

	"github.com/srohatgi/tinycert"
)

func Test_CA(t *testing.T) {
	sess := tinycert.NewSession()

	err := sess.Connect()
	if err != nil {
		t.Fatal("unable to create session", err)
	}

	defer func() {
		sess.Disconnect()
	}()

	ca := tinycert.NewCA(sess)

	caId, err := ca.Create("splunk", "ca", "ca", "US", "sha256")
	if err != nil {
		t.Fatal("unable to create ca", err)
	}

	t.Log("caid created: ", *caId)

	pem, err := ca.Get(*caId)
	if err != nil {
		t.Fatal("error getting pem", err)
	}

	t.Log("pem recieved: ", *pem)

	err = ca.Delete(*caId)
	if err != nil {
		t.Fatal("unable to delete ca", err)
	}

	// get list of ca
	res, err := ca.List()
	if err != nil {
		t.Fatal("failed getting ca list", err)
	}

	for _, item := range res {
		log.Printf("res: %+v\n", item)
		info, err := ca.Details(item.Id)
		if err != nil {
			t.Fatal("unable to fetch details", err)
		}
		log.Printf("info = %+v\n", info)
	}
}
