package auth

import (
  "context"
  "net/http"

  . "github.com/Liquid-Labs/terror/go/terror"
  "github.com/Liquid-Labs/go-rest/rest"
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
