package policy

import (
	"encoding/json"
	"fmt"
	"os"
)

// PolicySpec is a specification for a policy.
type PolicySpec struct {
	// Role is the role of the user making the request.
	// "*" matches all roles.
	Role string `json:"role"`
	// User is the user-id this rule applies to.
	// Either user or group is required to match the request.
	// "*" matches all users.
	User string `json:"user"`
	// Group is the group-id this rule applies to.
	// Either user or group is required to match the request.
	// "*" matches all groups.
	Group string `json:"group"`
	// Resource is the name of a resource. Resource, and Namespace are required to match resource requests.
	// "*" matches all resources
	Resource string `json:"resource"`
	// Namespace is the name of a namespace. APIGroup, Resource, and Namespace are required to match resource requests.
	// "*" matches all namespaces (including unnamespaced requests)
	Namespace string `json:"namespace"`
	// Readonly matches readonly requests when true, and all requests when false
	ReadOnly bool `json:"readonly"`
	// NonResourcePath matches non-resource request paths.
	// "*" matches all paths
	// "/foo/*" matches all subpaths of foo
	NonResourcePath string `json:"nonResourcePath"`
}

// UserAttributes holds user-related attributes.
type UserAttributes struct {
	// UserID is the user-id of the user making the request.
	UserID string `json:"userID"`
	// GroupID is the group-id the user belongs to.
	GroupID string `json:"groupID"`
	// Roles is the list of roles the user has.
	Roles []string `json:"roles"`
}

// ResourceAttributes holds resource-related attributes.
type ResourceAttributes struct {
	// Resource is the name of a resource.
	Resource string `json:"resource"`
	// Namespace is the name of a namespace.
	Namespace string `json:"namespace"`
	// ReadOnly is true for read-only requests.
	ReadOnly bool `json:"readOnly"`
}

// WithDefaultPolicies adds default policies to the PolicyManager.
func WithDefaultPolicies() PolicyOption {
	return func(p *PolicyManager) {
		p.policies = append(p.policies, defaultPolicies()...)
	}
}

// WithPolicies adds additional policies to the PolicyManager.
func WithPolicies(policies ...PolicySpec) PolicyOption {
	return func(p *PolicyManager) {
		p.policies = append(p.policies, policies...)
	}
}

// WithPoliciesFromFile loads policies from a JSON file and adds them to the PolicyManager.
func WithPoliciesFromFile(filename string) PolicyOption {
	return func(p *PolicyManager) {
		file, err := os.Open(filename)
		if err != nil {
			panic(fmt.Sprintf("failed to open policies file: %v", err))
		}
		defer file.Close()

		var newPolicies []PolicySpec
		if err := json.NewDecoder(file).Decode(&newPolicies); err != nil {
			panic(fmt.Sprintf("failed to decode policies from file: %v\n", err))
		}

		p.policies = append(p.policies, newPolicies...)
	}
}

// defaultPolicies returns the default set of policies.
func defaultPolicies() []PolicySpec {
	// Return an empty slice or define default policies here.
	return []PolicySpec{
		{Role: "*", User: "*", Group: "*", Resource: "*", Namespace: "*", ReadOnly: true, NonResourcePath: "*"},
		{Role: "admin", User: "*", Group: "*", Resource: "*", Namespace: "*", ReadOnly: false, NonResourcePath: "*"},
	}
}

// PolicyManager is an ABAC policy engine.
//
// We use ABAC (Attribute-Based Access Control) to define policies.
type PolicyManager struct {
	policies []PolicySpec
}

// PolicyOption defines a function that applies a configuration to the PolicyManager.
type PolicyOption func(*PolicyManager)

// NewPolicyManager initializes a new policy manager with optional policies.
func NewPolicyManager(opts ...PolicyOption) *PolicyManager {
	p := &PolicyManager{}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Evaluate checks if any policy allows the action based on user and resource attributes.
func (p *PolicyManager) Evaluate(user *UserAttributes, resource *ResourceAttributes) bool {
	for _, policy := range p.policies {
		if p.matchPolicy(policy, user, resource) {
			return true
		}
	}
	return false
}

// matchPolicy checks if a policy matches the provided user and resource attributes.
func (p *PolicyManager) matchPolicy(policy PolicySpec, user *UserAttributes, resource *ResourceAttributes) bool {
	return matchesSlice(policy.Role, user.Roles) &&
		matchesString(policy.User, user.UserID) &&
		matchesString(policy.Group, user.GroupID) &&
		matchesString(policy.Resource, resource.Resource) &&
		matchesString(policy.Namespace, resource.Namespace) &&
		matchesString(policy.NonResourcePath, resource.Resource) &&
		(policy.ReadOnly == resource.ReadOnly)
}

// matchesSlice checks if a value is in a list or matches a wildcard "*".
func matchesSlice(pattern string, list []string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	for _, v := range list {
		if v == pattern {
			return true
		}
	}
	return false
}

// matchesString checks if a single value matches a specified pattern or wildcard "*".
func matchesString(pattern, value string) bool {
	return pattern == "*" || pattern == "" || pattern == value
}
