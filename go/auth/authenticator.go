package auth

import (
  "context"
  "fmt"
  "net/http"
  "strings"

  fbauth "firebase.google.com/go/auth"
  "firebase.google.com/go"

  "github.com/Liquid-Labs/env/go/env"
  . "github.com/Liquid-Labs/terror/go/terror"
  "github.com/Liquid-Labs/go-rest/rest"
  "google.golang.org/api/option"
)

// AuthOracle defines the interface for detecting and extracting authentication information from an HTTP request. In live usage, `SetAuthorizationContext` is used to inject an AuthOracle into the request context for use in downstream processing. Downstream handlers can access the AuthOracle via GetFromContext.
type AuthOracle interface {
  // InitFromRequest initialaizes an authentic from an HTTP request. This is typically called by the HTTP handler SetAuthorizationContext. This method expects an empty, non-nil reciever.
  InitFromRequest(*http.Request) Terror

  // GetFromContext extracts the AuthOracle cached in the context for used in downstream request processing. This method expects an empty, non-nil reciever.
  GetFromContext(context.Context) Terror

  // RquireAuthentication creates an appropriate, typed error if the request is not authenticated.
  RequireAuthentication() Terror

  // IsRequestAuthenticated returns true if the request is authenticated, and false otherwise.
  IsRequestAuthenticated() bool

  // GetAuthID returns the authenticated user's authorization ID as maintained by the authentication provider. This is distinct from our own ID.
  GetAuthID() string

  // GetRequest returns the HTTP request which was processed to determine authentication. The request is usually available from the handler, and this is provided as a convenience.
  GetRequest() *http.Request
}

type Claimant interface {
  // HasAllClaims returns true if the authenticated user has all the indicated claims.
  HasAllClaims(claims ...string) bool

  // RequireAllClaims returns a typed error unless the authenticated user has all the indicated claims.
  RequireAllClaims(claims ...string) Terror

  // HasAnyClaim returns true if the authenticated user has any of the indicated claims.
  HasAnyClaim(claims ...string) bool

  // RequireAnyClaim returns a typed error unless the authenticated user has at least on of the indicated claims.
  RequireAnyClaims()

  // GetClaims provides a list of the claims held by the authenticated user. If the user has no claims, or is not authenticated, this will be an empty, non-nil list.
  GetClaims() []string
}

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

const credsKey string = "FIREBASE_CREDS_FILE"
var fbConfig = &firebase.Config{}
var fbClientOptions option.ClientOption

func init() {
  if env.IsDev() {
    localFirebaseCredsFile := env.MustGet(credsKey)
    fbClientOptions = option.WithCredentialsFile(localFirebaseCredsFile)
  }
}

type authOracleKey string
const AuthOracleKey authOracleKey = authOracleKey(`lc-authOracle`)

// SetAuthorizationContext initializes an AuthOracle and is intended for use as the first or an early member of the rquest processing chain. To use a specific AuthOracle implementation (tied to a specific authentication provider, or for testing), simply place an empty, non-nill struct of the approprite type implementing AuthOracle in the request context using `AuthOracleKey`. If no such stuct is found, we default to the FbOracle.
func SetAuthorizationContext(next http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    authOracle := r.Context().Value(AuthOracleKey).(AuthOracle)
    if authOracle == nil {
      authOracle = &FbOracle{}
    }
    if err := authOracle.InitFromRequest(r); err != nil {
      rest.HandleError(w, err)
    } else {
      // cache the oracle on the context for downstream use
      next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), AuthOracleKey, authOracle)))
    }
  })
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
