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
	"sort"
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

type fvColl []*fieldValues

func (fv fvColl) Len() int {
	return len(fv)
}

func (fv fvColl) Less(i, j int) bool {
	return fv[i].name < fv[j].name
}

func (fv fvColl) Swap(i, j int) {
	fv[i], fv[j] = fv[j], fv[i]
}

func (s *Session) makeCall(api string, list fvColl, response interface{}) (interface{}, error) {
	if s.token != nil {
		list = append(list, &fieldValues{"token", *s.token})
	}

	sort.Sort(list)

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

type CA struct {
	session *Session
}

func NewCA(session *Session) *CA {
	return &CA{
		session: session,
	}
}

func (ca *CA) Create(orgName, locality, stateCode, countryCode, hashMethod string) (caId *int64, err error) {
	list := []*fieldValues{
		{"C", countryCode},
		{"L", locality},
		{"O", orgName},
		{"ST", stateCode},
		{"hash_method", hashMethod},
	}

	type idResponse struct {
		CaId int64 `json:"ca_id"`
	}

	res, err := ca.session.makeCall("ca/new", list, &idResponse{})
	if err != nil {
		return
	}
	caId = &res.(*idResponse).CaId
	return
}

func (ca *CA) List() (items []*CAListItem, err error) {
	res, err := ca.session.makeCall("ca/list", []*fieldValues{}, &[]*CAListItem{})
	if err != nil {
		return
	}
	items = *res.(*[]*CAListItem)
	return
}

func (ca *CA) Details(caId int64) (caInfo *CAInfo, err error) {
	res, err := ca.session.makeCall("ca/details", []*fieldValues{{"ca_id", caId}}, &CAInfo{})
	if err != nil {
		return
	}
	caInfo = res.(*CAInfo)
	return
}

func (ca *CA) Get(caId int64) (pem *string, err error) {
	type pemInfo struct {
		Pem string `json:"pem"`
	}
	res, err := ca.session.makeCall("ca/details", []*fieldValues{{"ca_id", caId}, {"what", "cert"}}, &pemInfo{})
	if err != nil {
		return
	}
	pem = &res.(*pemInfo).Pem
	return
}

func (ca *CA) Delete(caId int64) (err error) {
	type deleted struct{}
	_, err = ca.session.makeCall("ca/delete", []*fieldValues{{"ca_id", caId}}, &deleted{})
	return
}

type CertificateStatus int

const (
	Expired CertificateStatus = 1
	Good                      = 2
	Revoked                   = 4
	Hold                      = 8
)

func (cs CertificateStatus) toString() string {
	switch cs {
	case Expired:
		return "expired"
	case Good:
		return "good"
	case Hold:
		return "hold"
	case Revoked:
		return "revoked"
	}
	return ""
}

type SAN struct {
	DNS   string
	Email string
	IP    string
	URI   string
}

type CertificateInfo struct {
	Id          int64  `json:"id"`
	Status      string `json:"status"`
	CountryCode string `json:"C"`
	StateCode   string `json:"ST"`
	Locality    string `json:"L"`
	OrgName     string `json:"O"`
	OrgUnit     string `json:"OU"`
	CommonName  string `json:"CN"`
	Alt         []SAN  `json:"alt"`
}

type CertificateListItem struct {
	Id      int64
	Name    string
	Status  string
	Expires int64
}

type Certificate struct {
	session *Session
}

func NewCertificate(session *Session) *Certificate {
	return &Certificate{session: session}
}

func (c *Certificate) Create(caId int64, commonName, orgUnit, orgName, locality, stateCode, countryCode string, alt []SAN) (certId *int64, err error) {
	list := []*fieldValues{
		{"C", countryCode},
		{"CN", commonName},
		{"L", locality},
		{"O", orgName},
		{"OU", orgUnit},
		{"ST", stateCode},
	}

	for index, san := range alt {
		prefix := fmt.Sprintf("SANs[%d]", index)
		if len(san.Email) > 0 {
			list = append(list, &fieldValues{prefix + "[email]", san.Email})
		}
		if len(san.DNS) > 0 {
			list = append(list, &fieldValues{prefix + "[DNS]", san.DNS})
		}
		if len(san.IP) > 0 {
			list = append(list, &fieldValues{prefix + "[IP]", san.IP})
		}
		if len(san.URI) > 0 {
			list = append(list, &fieldValues{prefix + "[URI]", san.URI})
		}
	}

	type idResponse struct {
		CertId int64 `json:"cert_id"`
	}

	res, err := c.session.makeCall("cert/new", list, &idResponse{})
	if err != nil {
		return
	}
	certId = &res.(*idResponse).CertId
	return
}

func (c *Certificate) Get(certId int64, what string) (result *string, err error) {
	type pemInfo struct {
		Pem    string `json:"pem"`
		Pkcs12 string `json:"pkcs12"`
	}
	res, err := c.session.makeCall("cert/details", []*fieldValues{{"cert_id", certId}, {"what", what}}, &pemInfo{})
	if err != nil {
		return
	}
	myPemInfo := res.(*pemInfo)
	if len(myPemInfo.Pem) > 0 {
		result = &myPemInfo.Pem
	} else {
		result = &myPemInfo.Pkcs12
	}
	return
}

func (c *Certificate) Details(certId int64) (certInfo *CertificateInfo, err error) {
	res, err := c.session.makeCall("cert/details", []*fieldValues{{"cert_id", certId}}, &CertificateInfo{})
	if err != nil {
		return
	}
	certInfo = res.(*CertificateInfo)
	return
}

func (c *Certificate) List(caId int64, status CertificateStatus) (list []*CertificateListItem, err error) {
	res, err := c.session.makeCall("cert/list", []*fieldValues{{"ca_id", caId}, {"what", status}}, &[]*CertificateListItem{})
	if err != nil {
		return
	}
	list = *res.(*[]*CertificateListItem)
	return
}

func (c *Certificate) Reissue(certId int64) (newCertId *int64, err error) {
	type idResponse struct {
		CertId int64 `json:"cert_id"`
	}

	res, err := c.session.makeCall("cert/reissue", []*fieldValues{{"cert_id", certId}}, &idResponse{})
	if err != nil {
		return
	}
	newCertId = &res.(*idResponse).CertId
	return
}

func (c *Certificate) Status(certId int64, status CertificateStatus) (err error) {
	type updated struct{}

	_, err = c.session.makeCall("cert/status", []*fieldValues{{"cert_id", certId}, {"status", status.toString()}}, &updated{})
	return
}
