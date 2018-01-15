package tinycert

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type Session struct {
	email      string
	passphrase string
	apiKey     string
	serverPath string
	clt        *http.Client
	token      *string
}

func NewSession() *Session {
	return &Session{
		serverPath: "https://www.tinycert.org/api/v1/",
		email:      os.Getenv("TINYCERT_EMAIL"),
		passphrase: os.Getenv("TINYCERT_PASSWORD"),
		apiKey:     os.Getenv("TINYCERT_APIKEY"),
		clt:        &http.Client{},
	}
}

func (s *Session) WithEmail(email string) *Session {
	s.email = email
	return s
}

func (s *Session) WithPassphrase(passphrase string) *Session {
	s.passphrase = passphrase
	return s
}

func (s *Session) WithApiKey(apiKey string) *Session {
	s.apiKey = apiKey
	return s
}

func (s *Session) Connect() (err error) {
	type connectResponse struct {
		Token string `json:"token"`
	}

	res, err := s.makeCall("connect", []*fieldValues{{"email", s.email}, {"passphrase", s.passphrase}}, &connectResponse{})
	if err != nil {
		return
	}

	cres := res.(*connectResponse)
	s.token = &cres.Token
	return
}

func (s *Session) Disconnect() (err error) {
	type disconnectResponse struct{}

	_, err = s.makeCall("disconnect", []*fieldValues{}, &disconnectResponse{})

	return
}

type fieldValues struct {
	name  string
	value interface{}
}

func (s *Session) makeCall(api string, list []*fieldValues, response interface{}) (interface{}, error) {
	if s.token != nil {
		list = append(list, &fieldValues{"token", *s.token})
	}

	// todo: sort the list

	vals := ""
	for _, fv := range list {
		if vals != "" {
			vals += "&"
		}
		vals += url.QueryEscape(fv.name) + "=" + url.QueryEscape(fmt.Sprintf("%v", fv.value))
	}

	mac := hmac.New(sha256.New, []byte(s.apiKey))
	mac.Write([]byte(vals))
	digest := hex.EncodeToString(mac.Sum(nil))

	vals += "&digest=" + url.QueryEscape(digest)

	log.Printf("payload: %s\n", vals)

	resp, err := s.clt.Post(s.serverPath+api, "application/x-www-form-urlencoded", strings.NewReader(vals))
	if err != nil {
		log.Printf("error calling tinycert", err)
		return nil, err
	}

	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("error from server code = %d, response = %s", resp.StatusCode, buf.String())
	}

	log.Printf("response from server: %s\n", buf.String())

	err = json.Unmarshal(buf.Bytes(), response)
	if err != nil {
		log.Printf("unable to unmarshal struct")
		return nil, err
	}

	return response, nil
}

type CAListItem struct {
	Id   int64  `json:"id"`
	Name string `json:"name"`
}

type CA struct {
	session *Session
}

func NewCA(session *Session) *CA {
	return &CA{
		session: session,
	}
}

func (ca *CA) List() (items []*CAListItem, err error) {
	res, err := ca.session.makeCall("ca/list", []*fieldValues{}, &[]*CAListItem{})
	if err != nil {
		return
	}
	items = *res.(*[]*CAListItem)
	return
}

func (ca *CA) Create(OrgName, Locality, StateCode, CountryCode, hashMethod string) (caId *int64, err error) {
	list := []*fieldValues{
		{"C", CountryCode},
		{"L", Locality},
		{"O", OrgName},
		{"ST", StateCode},
		{"hash_method", hashMethod},
	}

	type idResponse struct {
		caId int64 `json:"ca_id"`
	}

	res, err := ca.session.makeCall("ca/new", list, &idResponse{})
	if err != nil {
		return
	}
	caId = &res.(*idResponse).caId
	return
}

type CAInfo struct {
	Id            int64  `json:"id"`
	CountryCode   string `json:"C"`
	StateCode     string `json:"ST"`
	Locality      string `json:"L"`
	OrgName       string `json:"O"`
	OrgUnit       string `json:"OU"`
	CommonName    string `json:"CN"`
	Email         string `json:"E"`
	HashAlgorithm string `json:"hash_alg"`
}

func (ca *CA) Details(caId int64) (caInfo *CAInfo, err error) {
	res, err := ca.session.makeCall("ca/details", []*fieldValues{{"ca_id", caId}}, &CAInfo{})
	if err != nil {
		return
	}
	caInfo = res.(*CAInfo)
	return
}
