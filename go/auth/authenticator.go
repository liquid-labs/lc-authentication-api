package auth

import (
  "fmt"
  "net/http"
  "strings"

  "firebase.google.com/go/auth"
  "firebase.google.com/go"

  "github.com/Liquid-Labs/env/go/env"
  "github.com/Liquid-Labs/terror/go/terror"
  "google.golang.org/api/option"
)

type Authenticator struct {
  firebaseAuthClient *auth.Client
  request            *http.Request
  token              *auth.Token
  aznID              string
  claims             map[string]interface{}
}

const credsKey string = "FIREBASE_CREDS_FILE"
var fbConfig = &firebase.Config{}
var fbClientOptions option.ClientOption

func init() {
  if env.IsDev() {
    localFirebaseCredsFile := env.MustGet(credsKey)
    fbClientOptions = option.WithCredentialsFile(localFirebaseCredsFile)
  }
}

func InitAuthenticator(r *http.Request) (*Authenticator, terror.Terror) {
	var app *firebase.App
	var err error
	if env.IsDev() {
		app, err = firebase.NewApp(r.Context(), fbConfig, fbClientOptions)
	} else {
		app, err = firebase.NewApp(r.Context(), fbConfig)
	}
  if err != nil {
    return nil, terror.ServerError("Could not access authentication service.", err)
  }

  authClient, err := app.Auth(r.Context())
  if err != nil {
    return nil, terror.ServerError("Could not access authenticaiton service.", err)
  }

  authHeader := r.Header.Get("Authorization")
  if authHeader == `` {
    return &Authenticator{authClient, r, nil, ``, map[string]interface{}{}}, nil
  } else {
    tokenString := strings.TrimPrefix(authHeader, "Bearer ")
    // TODO: use VerifyIDTokenAndCheckRevoked?
  	token, err := authClient.VerifyIDToken(r.Context(), tokenString)
  	if err != nil {
  		return nil, terror.AuthorizationError("Could not decode HTTP authorizaiton token.", err)
  	} else {
      aznID := token.UID
      claims := token.Claims

      return &Authenticator{authClient, r, token, aznID, claims}, nil
    }
  }
}

func (a *Authenticator) GetFirebaseAuthClient() (*auth.Client) {
  return a.firebaseAuthClient
}

func (a *Authenticator) IsRequestAuthenticated() (bool) {
  return a.aznID != ``
}

func (a *Authenticator) GetAznID() (string) {
  return a.aznID
}

func (a *Authenticator) HasAllClaims(req ...string) (bool) {
  claims := a.token.Claims
  for _, reqClaim := range req {
    claim, ok := claims[reqClaim]
    if !ok || !claim.(bool) {
      return false
    }
  }

  return true
}

func (a *Authenticator) RequireAllClaims(req ...string) (bool, terror.Terror) {
  passes := a.HasAllClaims(req...)
  if !passes {
    return false, terror.AuthorizationError(fmt.Sprintf("Access to resource requires claims '%s'.", strings.Join(req, `', '`)), nil)
  } else {
    return true, nil
  }
}

func (a *Authenticator) HasAnyClaim(req ...string) (bool) {
  claims := a.token.Claims
  for _, reqClaim := range req {
    claim, ok := claims[reqClaim]
    if ok && claim.(bool) {
      return true
    }
  }

  return false
}

func (a *Authenticator) RequireAnyClaim(req ...string) (bool, terror.Terror) {
  passes := a.HasAnyClaim(req...)
  if !passes {
    return false, terror.AuthorizationError(fmt.Sprintf("Access to resource requires any claim '%s'.", strings.Join(req, `', '`)), nil)
  } else {
    return true, nil
  }
}

func (a *Authenticator) GetRequest() (*http.Request) {
  return a.request
}
