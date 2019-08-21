// Code generated by MockGen. DO NOT EDIT.
// Source: auth/authenticator.go

// Package mock is a generated GoMock package.
package mock

import (
	. "github.com/Liquid-Labs/terror/go/terror"
	gomock "github.com/golang/mock/gomock"
	http "net/http"
	reflect "reflect"
)

// MockAuthOracle is a mock of AuthOracle interface
type MockAuthOracle struct {
	ctrl     *gomock.Controller
	recorder *MockAuthOracleMockRecorder
}

// MockAuthOracleMockRecorder is the mock recorder for MockAuthOracle
type MockAuthOracleMockRecorder struct {
	mock *MockAuthOracle
}

// NewMockAuthOracle creates a new mock instance
func NewMockAuthOracle(ctrl *gomock.Controller) *MockAuthOracle {
	mock := &MockAuthOracle{ctrl: ctrl}
	mock.recorder = &MockAuthOracleMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockAuthOracle) EXPECT() *MockAuthOracleMockRecorder {
	return m.recorder
}

// InitFromRequest mocks base method
func (m *MockAuthOracle) InitFromRequest(arg0 *http.Request) Terror {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InitFromRequest", arg0)
	ret0, _ := ret[0].(Terror)
	return ret0
}

// InitFromRequest indicates an expected call of InitFromRequest
func (mr *MockAuthOracleMockRecorder) InitFromRequest(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InitFromRequest", reflect.TypeOf((*MockAuthOracle)(nil).InitFromRequest), arg0)
}

// RequireAuthentication mocks base method
func (m *MockAuthOracle) RequireAuthentication() Terror {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RequireAuthentication")
	ret0, _ := ret[0].(Terror)
	return ret0
}

// RequireAuthentication indicates an expected call of RequireAuthentication
func (mr *MockAuthOracleMockRecorder) RequireAuthentication() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RequireAuthentication", reflect.TypeOf((*MockAuthOracle)(nil).RequireAuthentication))
}

// IsRequestAuthenticated mocks base method
func (m *MockAuthOracle) IsRequestAuthenticated() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsRequestAuthenticated")
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsRequestAuthenticated indicates an expected call of IsRequestAuthenticated
func (mr *MockAuthOracleMockRecorder) IsRequestAuthenticated() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsRequestAuthenticated", reflect.TypeOf((*MockAuthOracle)(nil).IsRequestAuthenticated))
}

// GetAuthID mocks base method
func (m *MockAuthOracle) GetAuthID() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAuthID")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetAuthID indicates an expected call of GetAuthID
func (mr *MockAuthOracleMockRecorder) GetAuthID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAuthID", reflect.TypeOf((*MockAuthOracle)(nil).GetAuthID))
}

// GetRequest mocks base method
func (m *MockAuthOracle) GetRequest() *http.Request {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRequest")
	ret0, _ := ret[0].(*http.Request)
	return ret0
}

// GetRequest indicates an expected call of GetRequest
func (mr *MockAuthOracleMockRecorder) GetRequest() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRequest", reflect.TypeOf((*MockAuthOracle)(nil).GetRequest))
}

// MockClaimant is a mock of Claimant interface
type MockClaimant struct {
	ctrl     *gomock.Controller
	recorder *MockClaimantMockRecorder
}

// MockClaimantMockRecorder is the mock recorder for MockClaimant
type MockClaimantMockRecorder struct {
	mock *MockClaimant
}

// NewMockClaimant creates a new mock instance
func NewMockClaimant(ctrl *gomock.Controller) *MockClaimant {
	mock := &MockClaimant{ctrl: ctrl}
	mock.recorder = &MockClaimantMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockClaimant) EXPECT() *MockClaimantMockRecorder {
	return m.recorder
}

// HasAllClaims mocks base method
func (m *MockClaimant) HasAllClaims(claims ...string) bool {
	m.ctrl.T.Helper()
	varargs := []interface{}{}
	for _, a := range claims {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "HasAllClaims", varargs...)
	ret0, _ := ret[0].(bool)
	return ret0
}

// HasAllClaims indicates an expected call of HasAllClaims
func (mr *MockClaimantMockRecorder) HasAllClaims(claims ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HasAllClaims", reflect.TypeOf((*MockClaimant)(nil).HasAllClaims), claims...)
}

// RequireAllClaims mocks base method
func (m *MockClaimant) RequireAllClaims(claims ...string) Terror {
	m.ctrl.T.Helper()
	varargs := []interface{}{}
	for _, a := range claims {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "RequireAllClaims", varargs...)
	ret0, _ := ret[0].(Terror)
	return ret0
}

// RequireAllClaims indicates an expected call of RequireAllClaims
func (mr *MockClaimantMockRecorder) RequireAllClaims(claims ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RequireAllClaims", reflect.TypeOf((*MockClaimant)(nil).RequireAllClaims), claims...)
}

// HasAnyClaim mocks base method
func (m *MockClaimant) HasAnyClaim(claims ...string) bool {
	m.ctrl.T.Helper()
	varargs := []interface{}{}
	for _, a := range claims {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "HasAnyClaim", varargs...)
	ret0, _ := ret[0].(bool)
	return ret0
}

// HasAnyClaim indicates an expected call of HasAnyClaim
func (mr *MockClaimantMockRecorder) HasAnyClaim(claims ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HasAnyClaim", reflect.TypeOf((*MockClaimant)(nil).HasAnyClaim), claims...)
}

// RequireAnyClaims mocks base method
func (m *MockClaimant) RequireAnyClaims() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "RequireAnyClaims")
}

// RequireAnyClaims indicates an expected call of RequireAnyClaims
func (mr *MockClaimantMockRecorder) RequireAnyClaims() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RequireAnyClaims", reflect.TypeOf((*MockClaimant)(nil).RequireAnyClaims))
}

// GetClaims mocks base method
func (m *MockClaimant) GetClaims() []string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetClaims")
	ret0, _ := ret[0].([]string)
	return ret0
}

// GetClaims indicates an expected call of GetClaims
func (mr *MockClaimantMockRecorder) GetClaims() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetClaims", reflect.TypeOf((*MockClaimant)(nil).GetClaims))
}
