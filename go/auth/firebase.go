package auth

import (
  "context"
  "fmt"
  "net/http"
  "strings"

  "firebase.google.com/go"
  "google.golang.org/api/option"

  fbauth "firebase.google.com/go/auth"
  "github.com/Liquid-Labs/env/go/env"
  . "github.com/Liquid-Labs/terror/go/terror"
)

const credsKey string = "FIREBASE_CREDS_FILE"
var fbConfig = &firebase.Config{}
var fbClientOptions option.ClientOption

type FbAuthOracle interface {
  // GetFirebaseAuthClient returns the underlying Firebase authentication/authorization client used to verify tokens and retrieve claims from google.
  GetFirebaseAuthClient() *fbauth.Client
}

type FbOracle struct {
  firebaseAuthClient *fbauth.Client
  request            *http.Request
  token              *fbauth.Token
  authID              string
  claims             map[string]interface{}
}

func init() {
  if env.IsDev() {
    localFirebaseCredsFile := env.MustGet(credsKey)
    fbClientOptions = option.WithCredentialsFile(localFirebaseCredsFile)
  }
}

func (auth *FbOracle) InitFromRequest(r *http.Request) (Terror) {
  auth.request = r

	var app *firebase.App
	var err error
	if env.IsDev() {
		app, err = firebase.NewApp(r.Context(), fbConfig, fbClientOptions)
	} else {
		app, err = firebase.NewApp(r.Context(), fbConfig)
	}
  if err != nil {
    return ServerError("Could not access authentication service.", err)
  }

  authClient, err := app.Auth(r.Context())
  auth.firebaseAuthClient = authClient
  if err != nil {
    return ServerError("Could not access authenticaiton service.", err)
  }

  authHeader := r.Header.Get("Authorization")
  if authHeader == `` {
    auth.token = nil
    auth.authID = ``
    auth.claims = map[string]interface{}{}
    return nil
  } else {
    tokenString := strings.TrimPrefix(authHeader, "Bearer ")
    // TODO: use VerifyIDTokenAndCheckRevoked?
  	token, err := authClient.VerifyIDToken(r.Context(), tokenString)
  	if err != nil {
  		return UnprocessableEntityError(fmt.Sprintf(`Could not decode HTTP authorizaiton token. (%s)`))
  	} else {
      auth.token = token
      auth.authID = token.UID
      auth.claims = token.Claims
      return nil
    }
  }
}

func (authOracle *FbOracle) GetFromContext(ctx context.Context) Terror {
  cachedOracle := ctx.Value(AuthOracleKey).(*FbOracle)
  if authOracle != nil {
    authOracle.firebaseAuthClient = cachedOracle.firebaseAuthClient
    authOracle.request = cachedOracle.request
    authOracle.token = cachedOracle.token
    authOracle.authID = cachedOracle.authID
    authOracle.claims = cachedOracle.claims
  }
  return nil
}

func (authOracle *FbOracle) RequireAuthentication() Terror {
  if !authOracle.IsRequestAuthenticated() {
    return UnauthenticatedError(`Non-Authenticated user cannot requested 'owned' items.`)
  }
  authID := authOracle.GetAuthID()
  if authID == `` {
    return ServerError(`Missing authorization ID for authenticated user.`, nil)
  }
  return nil
}

func (a *FbOracle) IsRequestAuthenticated() (bool) {
  return a != nil && a.authID != ``
}

func (a *FbOracle) SetAuthID(authID string) Terror {
  if env.IsProduction() {
    return BadRequestError(`Attempt to set AZN ID in production.`)
  } else {
    a.authID = authID
    return nil
  }
}

func (a *FbOracle) GetAuthID() (string) {
  if a == nil {
    return ``
  } else { return a.authID }
}

func (a *FbOracle) HasAllClaims(req ...string) (bool) {
  claims := a.token.Claims
  for _, reqClaim := range req {
    claim, ok := claims[reqClaim]
    if !ok || !claim.(bool) {
      return false
    }
  }

  return true
}

func (a *FbOracle) RequireAllClaims(req ...string) Terror {
  passes := a.HasAllClaims(req...)
  if !passes {
    return ForbiddenError(fmt.Sprintf("Access to resource requires claims '%s'.", strings.Join(req, `', '`)))
  } else { return nil }
}

func (a *FbOracle) HasAnyClaim(req ...string) (bool) {
  claims := a.token.Claims
  for _, reqClaim := range req {
    claim, ok := claims[reqClaim]
    if ok && claim.(bool) {
      return true
    }
  }

  return false
}

func (a *FbOracle) RequireAnyClaim(req ...string) Terror {
  passes := a.HasAnyClaim(req...)
  if !passes {
    return ForbiddenError(fmt.Sprintf("Access to resource requires any claim '%s'.", strings.Join(req, `', '`)))
  } else { return nil }
}

func (a *FbOracle) GetClaims() []string {
  list := make([]string, 0, len(a.claims))
  for claim, ok := range a.claims {
    if ok.(bool) { list = append(list, claim) }
  }
  return list
}

func (a *FbOracle) GetFirebaseAuthClient() (*fbauth.Client) {
  return a.firebaseAuthClient
}

func (a *FbOracle) GetRequest() (*http.Request) {
  return a.request
}
