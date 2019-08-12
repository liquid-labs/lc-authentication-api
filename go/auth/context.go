package auth

import (
  "context"
  "net/http"

  "github.com/Liquid-Labs/go-rest/rest"
)

type authenticatorKey string
const AuthenticatorKey authenticatorKey = authenticatorKey(`lc-authenticator`)

// setAuthorizationContext retrieves the Firebase authorization token from the
// incoming HTTP request, if present, and adds it the request context for use
// by downstream handlers.
func SetAuthorizationContext(next http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    if authenticator, err := InitAuthenticator(r); err != nil {
      rest.HandleError(w, err)
    } else {
      next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), AuthenticatorKey, authenticator)))
    }
  })
}

func GetAuthenticator(ctx context.Context) Authenticator {
  return ctx.Value(AuthenticatorKey).(Authenticator)
}
