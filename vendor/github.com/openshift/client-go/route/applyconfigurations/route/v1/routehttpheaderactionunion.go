// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1

import (
	routev1 "github.com/openshift/api/route/v1"
)

// RouteHTTPHeaderActionUnionApplyConfiguration represents a declarative configuration of the RouteHTTPHeaderActionUnion type for use
// with apply.
type RouteHTTPHeaderActionUnionApplyConfiguration struct {
	Type *routev1.RouteHTTPHeaderActionType    `json:"type,omitempty"`
	Set  *RouteSetHTTPHeaderApplyConfiguration `json:"set,omitempty"`
}

// RouteHTTPHeaderActionUnionApplyConfiguration constructs a declarative configuration of the RouteHTTPHeaderActionUnion type for use with
// apply.
func RouteHTTPHeaderActionUnion() *RouteHTTPHeaderActionUnionApplyConfiguration {
	return &RouteHTTPHeaderActionUnionApplyConfiguration{}
}

// WithType sets the Type field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Type field is set to the value of the last call.
func (b *RouteHTTPHeaderActionUnionApplyConfiguration) WithType(value routev1.RouteHTTPHeaderActionType) *RouteHTTPHeaderActionUnionApplyConfiguration {
	b.Type = &value
	return b
}

// WithSet sets the Set field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Set field is set to the value of the last call.
func (b *RouteHTTPHeaderActionUnionApplyConfiguration) WithSet(value *RouteSetHTTPHeaderApplyConfiguration) *RouteHTTPHeaderActionUnionApplyConfiguration {
	b.Set = value
	return b
}
