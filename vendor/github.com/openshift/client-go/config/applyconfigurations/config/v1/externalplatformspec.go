// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1

// ExternalPlatformSpecApplyConfiguration represents a declarative configuration of the ExternalPlatformSpec type for use
// with apply.
type ExternalPlatformSpecApplyConfiguration struct {
	PlatformName *string `json:"platformName,omitempty"`
}

// ExternalPlatformSpecApplyConfiguration constructs a declarative configuration of the ExternalPlatformSpec type for use with
// apply.
func ExternalPlatformSpec() *ExternalPlatformSpecApplyConfiguration {
	return &ExternalPlatformSpecApplyConfiguration{}
}

// WithPlatformName sets the PlatformName field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the PlatformName field is set to the value of the last call.
func (b *ExternalPlatformSpecApplyConfiguration) WithPlatformName(value string) *ExternalPlatformSpecApplyConfiguration {
	b.PlatformName = &value
	return b
}
