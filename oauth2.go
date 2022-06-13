// Go implementation of the OAuth 2.0 Authorization Framework
// https://tools.ietf.org/html/rfc6749
package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client represents an OAuth 2.0 client.
type Client struct {
	// ClientID is the client identifier issued to the client during the
	// registration process.
	ClientID string

	// ClientSecret is the client secret.  The client may set this, but if not
	// it will be filled in by the authorization server.
	ClientSecret string

	// RedirectURL is the URL to redirect users going through
	// the OAuth flow, after the resource owner's URLs.
	RedirectURL string

	// Scope specifies optional requested permissions.
	Scopes []string

	// Endpoint contains the resource server's authorization and token
	// endpoints.
	Endpoint Endpoint

	// HTTPClient is the http.Client used to communicate with the OAuth2 server.
	// If nil, http.DefaultClient is used.
	HTTPClient *http.Client
}

// Endpoint contains the resource server's authorization and token
// endpoints.
type Endpoint struct {
	// AuthURL is the resource server's authorization endpoint
	// URLs.
	AuthURL string

	// TokenURL is the resource server's token endpoint
	// URLs.
	TokenURL string
}

// AuthCodeURL returns a URL to OAuth 2.0 provider's consent page
// that asks for permissions for the required scopes explicitly.
//
// State is a token to protect the user from CSRF attacks. You must
// always provide a non-zero string and validate that it matches the
// the state query parameter on your redirect callback.
// See http://tools.ietf.org/html/rfc6749#section-10.12 for more info.
//
// Opts may contain a list of additional options.
func (c *Client) AuthCodeURL(state string, opts ...AuthCodeOption) string {
	var u url.URL
	u.Scheme = "https"
	u.Host = "accounts.google.com"
	u.Path = "/o/oauth2/auth"
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", c.ClientID)
	q.Set("redirect_uri", c.RedirectURL)
	q.Set("scope", strings.Join(c.Scopes, " "))
	q.Set("state", state)
	for _, opt := range opts {
		opt.setValue(&q)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// AuthCodeOption is an option for the AuthCodeURL function.
type AuthCodeOption interface {
	setValue(*url.Values)
}

// AuthCodeOptions is a collection of AuthCodeOption.
type AuthCodeOptions []AuthCodeOption

// AccessType is an AuthCodeOption that represents the access type.
type AccessType string

// SetAccessType sets the access type.
func SetAccessType(t AccessType) AuthCodeOption {
	return accessType(t)
}

type accessType AccessType

func (a accessType) setValue(v *url.Values) {
	v.Set("access_type", string(a))
}

// ApprovalForce is an AuthCodeOption that represents the approval force.
type ApprovalForce string

// SetApprovalForce sets the approval force.
func SetApprovalForce(f ApprovalForce) AuthCodeOption {
	return approvalForce(f)
}

type approvalForce ApprovalForce

func (a approvalForce) setValue(v *url.Values) {
	v.Set("approval_prompt", string(a))
}

// LoginHint is an AuthCodeOption that represents the login hint.
type LoginHint string

// SetLoginHint sets the login hint.
func SetLoginHint(h LoginHint) AuthCodeOption {
	return loginHint(h)
}

type loginHint LoginHint

func (l loginHint) setValue(v *url.Values) {
	v.Set("login_hint", string(l))
}

// Prompt is an AuthCodeOption that represents the prompt.
type Prompt string

// SetPrompt sets the prompt.
func SetPrompt(p Prompt) AuthCodeOption {
	return prompt(p)
}

type prompt Prompt

func (p prompt) setValue(v *url.Values) {
	v.Set("prompt", string(p))
}

// Token represents the credentials used to authorize
// the requests to access protected resources on the OAuth 2.0
// provider's backend.
//
// Most users of this package should not access fields of Token
// directly. They're exported mostly for use by related packages
// implementing derivative OAuth2 flows.
type Token struct {
	// AccessToken is the token that authorizes and authenticates
	// the requests.
	AccessToken string `json:"access_token"`

	// TokenType is the type of token.
	// The Type method returns either this or "Bearer", the default.
	TokenType string `json:"token_type,omitempty"`

	// RefreshToken is a token that's used by the application
	// (as opposed to the user) to refresh the access token
	// if it expires.
	RefreshToken string `json:"refresh_token,omitempty"`

	// Expiry is the optional expiration time of the access token.
	//
	// If zero, TokenSource implementations will reuse the same
	// token forever and RefreshToken or equivalent
	// mechanisms for that TokenSource will not be used.
	Expiry time.Time `json:"expiry,omitempty"`

	// raw optionally contains extra metadata from the server
	// when updating a token.
	raw interface{}
}

// Type returns t.TokenType if non-empty, else "Bearer".
func (t *Token) Type() string {
	if t.TokenType == "" {
		return "Bearer"
	}
	return t.TokenType
}

// SetAuthHeader sets the Authorization header to r using the access
// token in t.
//
// This method is unnecessary when using Transport or an HTTP Client
// returned by this package.
func (t *Token) SetAuthHeader(r *http.Request) {
	r.Header.Set("Authorization", t.Type()+" "+t.AccessToken)
}

// Extra returns an extra field. Extra fields are key-value pairs returned
// by the server as a JSON object, stored as a map[string]interface{} in
// Token.raw.
//
// Extra fields are rarely used, and the format for the values is not
// specified.
//
// If the server response contains a field named "id_token", the value of
// that field is parsed and returned as an *IDToken instead.
func (t *Token) Extra(key string) (interface{}, bool) {
	if t.raw != nil {
		m, ok := t.raw.(map[string]interface{})
		if ok {
			v, ok := m[key]
			return v, ok
		}
	}
	return nil, false
}

// IDToken is a set of claims representing information about an end user.
//
// See http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
type IDToken struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	Expiry    int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
	Nonce     string `json:"nonce"`
	AuthTime  int64  `json:"auth_time"`
	AuthLevel int    `json:"acr"`
}

// Valid reports whether the ID token is valid.
//
// It checks the expiration time and nonce.
func (t *IDToken) Valid() bool {
	if t.Expiry < time.Now().Unix() {
		return false
	}
	if t.Nonce == "" {
		return false
	}
	return true
}

// Exchange converts an authorization code into a token.
//
// This is a shared method between Confidential and Public clients.
func (c *Client) Exchange(ctx context.Context, code string) (*Token, error) {
	v := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {c.RedirectURL},
	}
	if c.ClientSecret != "" {
		v.Set("client_id", c.ClientID)
		v.Set("client_secret", c.ClientSecret)
	} else {
		v.Set("client_id", c.ClientID)
	}
	req, err := http.NewRequest("POST", c.Endpoint.TokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(ctx)
	return c.doRequest(req)
}

// doRequest performs the HTTP request and returns a token or an error.
func (c *Client) doRequest(req *http.Request) (*Token, error) {
	if c.HTTPClient == nil {
		c.HTTPClient = http.DefaultClient
	}
	r, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	if code := r.StatusCode; code < 200 || code > 299 {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v\nResponse: %s", r.Status, body)
	}
	var token Token
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, err
	}
	if token.AccessToken == "" {
		return nil, errors.New("oauth2: server response missing access_token")
	}
	return &token, nil
}
