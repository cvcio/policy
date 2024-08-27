package policy_test

import (
	"testing"

	"github.com/cvcio/policy"
)

func TestPolicyManager_Evaluate(t *testing.T) {
	// Define test cases
	testCases := []struct {
		name               string
		policies           []policy.PolicySpec
		userAttributes     *policy.UserAttributes
		resourceAttributes *policy.ResourceAttributes
		expectedResult     bool
	}{
		{
			name: "Matching policy",
			policies: []policy.PolicySpec{
				{
					Role:     "admin",
					User:     "user1",
					Resource: "resource1",
				},
			},
			userAttributes: &policy.UserAttributes{
				UserID:  "user1",
				GroupID: "group1",
				Roles:   []string{"admin"},
			},
			resourceAttributes: &policy.ResourceAttributes{
				Resource:  "resource1",
				Namespace: "namespace1",
				ReadOnly:  false,
			},
			expectedResult: true,
		},
		{
			name: "Non-matching policy",
			policies: []policy.PolicySpec{
				{
					Role:     "admin",
					User:     "user1",
					Resource: "resource1",
				},
			},
			userAttributes: &policy.UserAttributes{
				UserID:  "user2",
				GroupID: "group1",
				Roles:   []string{"admin"},
			},
			resourceAttributes: &policy.ResourceAttributes{
				Resource:  "resource1",
				Namespace: "namespace1",
				ReadOnly:  false,
			},
			expectedResult: false,
		},
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a new policy manager with the test policies
			pm := policy.NewPolicyManager(policy.WithPolicies(tc.policies...))

			// Evaluate the policies against the user and resource attributes
			result := pm.Evaluate(tc.userAttributes, tc.resourceAttributes)

			// Check if the result matches the expected result
			if result != tc.expectedResult {
				t.Errorf("Expected %v, but got %v", tc.expectedResult, result)
			}
		})
	}
}
