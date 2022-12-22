package httputils

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
)

type Auth struct {
	CAFile             string `json:"ca_file,omitempty" yaml:"ca_file,omitempty" mapstructure:"ca_file,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty" yaml:"insecure_skip_verify,omitempty" mapstructure:"insecure_skip_verify,omitempty"`
	Password           string `json:"password,omitempty" yaml:"password,omitempty" mapstructure:"password,omitempty"`
	Token              string `json:"token,omitempty" yaml:"token,omitempty" mapstructure:"token,omitempty"`
	Type               string `json:"type,omitempty" yaml:"type,omitempty" mapstructure:"type,omitempty"`
	Username           string `json:"username,omitempty" yaml:"username,omitempty" mapstructure:"username,omitempty"`
}

const (
	AuthTypeBearer = "Bearer"
	AuthTypeBasic  = "Basic"
)

type authRoundTripper struct {
	auth       string
	originalRT http.RoundTripper
}

type customHeadersRoundTripper struct {
	headers    map[string]string
	originalRT http.RoundTripper
}

func (rt *authRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", rt.auth)
	return rt.originalRT.RoundTrip(req)
}

func (rt *customHeadersRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// note: no need to check for nil or empty map - newCustomHeadersRoundTripper will assure us there will always be at least 1
	for k, v := range rt.headers {
		req.Header.Set(k, v)
	}
	return rt.originalRT.RoundTrip(req)
}

func newAuthRoundTripper(auth *Auth, rt http.RoundTripper) http.RoundTripper {
	switch auth.Type {
	case AuthTypeBearer:
		token := auth.Token
		return &authRoundTripper{auth: "Bearer " + token, originalRT: rt}
	case AuthTypeBasic:
		encoded := base64.StdEncoding.EncodeToString([]byte(auth.Username + ":" + auth.Password))
		return &authRoundTripper{auth: "Basic " + encoded, originalRT: rt}
	default:
		return rt
	}
}

func newCustomHeadersRoundTripper(headers map[string]string, rt http.RoundTripper) http.RoundTripper {
	if len(headers) == 0 {
		// if there are no custom headers then there is no need for a special RoundTripper; therefore just return the original RoundTripper
		return rt
	}
	return &customHeadersRoundTripper{
		headers:    headers,
		originalRT: rt,
	}
}

// Creates a new HTTP Transport with TLS, Timeouts, and optional custom headers.
//
// Please remember that setting long timeouts is not recommended as it can make
// idle connections stay open for as long as 2 * timeout. This should only be
// done in cases where you know the request is very likely going to be reused at
// some point in the near future.
func CreateTransport(auth *Auth, transportConfig *http.Transport, customHeaders map[string]string) (http.RoundTripper, error) {

	// We might need some custom RoundTrippers to manipulate the requests (for auth and other custom request headers).
	// Chain together the RoundTrippers that we need, retaining the outer-most round tripper so we can return it.
	outerRoundTripper := newCustomHeadersRoundTripper(customHeaders, transportConfig)

	if auth != nil {
		tlscfg, err := GetTLSConfig(auth)
		if err != nil {
			return nil, err
		}
		if tlscfg != nil {
			transportConfig.TLSClientConfig = tlscfg
		}
		outerRoundTripper = newAuthRoundTripper(auth, outerRoundTripper)
	}

	return outerRoundTripper, nil
}

func GetTLSConfig(auth *Auth) (*tls.Config, error) {
	if auth.InsecureSkipVerify || auth.CAFile != "" {
		var certPool *x509.CertPool
		if auth.CAFile != "" {
			certPool = x509.NewCertPool()
			cert, err := os.ReadFile(auth.CAFile)

			if err != nil {
				return nil, fmt.Errorf("failed to get root CA certificates: %s", err)
			}

			if ok := certPool.AppendCertsFromPEM(cert); !ok {
				return nil, fmt.Errorf("supplied CA file could not be parsed")
			}
		}
		return &tls.Config{
			InsecureSkipVerify: auth.InsecureSkipVerify,
			RootCAs:            certPool,
		}, nil
	}
	return nil, nil
}
