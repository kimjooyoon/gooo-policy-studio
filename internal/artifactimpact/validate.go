package artifactimpact

import (
	"strings"
	"unicode"

	"github.com/kimjooyoon/gooo-policy-studio/internal/admission"
	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactpreflight"
	"github.com/kimjooyoon/gooo-policy-studio/internal/completion"
	"github.com/kimjooyoon/gooo-policy-studio/internal/jsoninput"
	"github.com/kimjooyoon/gooo-policy-studio/internal/machinerules"
	"github.com/kimjooyoon/gooo-policy-studio/internal/policy"
)

type prepared struct {
	caseInput     Case
	before, after admission.ArtifactPolicy
	inputs        InputBindings
	source        Identity
	base          policy.Receipt
	permission    Permission
}

func baseInput(c Case) policy.Input {
	return policy.Input{Request: c.Request, Reviewer: policy.Reviewer{Key: c.Principal.Key, Team: c.Principal.Team, Active: c.Principal.Active}, Before: c.BaseRules, After: c.BaseRules}
}
func requirement(c Case) artifactpreflight.Requirement {
	return artifactpreflight.Requirement{Path: c.Artifact.Path, ExpectedSHA256: c.Artifact.ExpectedSHA256}
}
func completionPolicy(p admission.ArtifactPolicy) completion.Policy {
	ids := make([]string, len(p.Recipe.Claims))
	for i, c := range p.Recipe.Claims {
		ids[i] = c.ID
	}
	return completion.Policy{Schema: completion.PolicySchema, PolicyID: p.ID, Revision: p.Revision, RequiredClaims: ids}
}
func approvalFacts() machinerules.ToolEffects {
	return machinerules.ToolEffects{MutatesTarget: true, MutatesSession: true, WritesFilesystem: true, Idempotent: true}
}
func controlFacts() machinerules.ToolEffects {
	return machinerules.ToolEffects{MutatesSession: true, WritesFilesystem: true, Idempotent: true}
}

func validateCase(c Case) bool {
	if c.Schema != CaseSchema || c.Artifact.DeadlineUnix <= 0 || artifactpreflight.ValidateRequirement(requirement(c)) != nil || policy.Validate(baseInput(c)) != nil {
		return false
	}
	for _, s := range []string{c.Request.Key, c.Request.Requester, c.Request.Team, c.Principal.Key, c.Principal.Team} {
		if strings.TrimSpace(s) == "" {
			return false
		}
		for _, r := range s {
			if unicode.IsControl(r) {
				return false
			}
		}
	}
	return true
}
func validatePolicy(p admission.ArtifactPolicy) bool {
	if p.Schema != admission.ArtifactPolicySchema || p.MaxAgeSeconds < 0 || p.MaxAgeSeconds > 86400 || artifactpreflight.ValidateRecipe(p.Recipe) != nil || completion.ValidatePolicy(completionPolicy(p)) != nil {
		return false
	}
	switch p.RequiredAuthority {
	case "unit", "integration", "protocol", "renderer", "packaged-process", "live-observation":
	default:
		return false
	}
	return true
}

func prepare(paths Paths) (prepared, string) {
	var p prepared
	caseRaw, err := readPrivate(paths.Case, MaxInputBytes)
	if err != nil {
		return p, "CASE_FILE_INVALID"
	}
	beforeRaw, err := readPrivate(paths.Before, MaxInputBytes)
	if err != nil {
		return p, "BEFORE_FILE_INVALID"
	}
	afterRaw, err := readPrivate(paths.After, MaxInputBytes)
	if err != nil {
		return p, "AFTER_FILE_INVALID"
	}
	if jsoninput.Decode(caseRaw, &p.caseInput, int(MaxInputBytes)) != nil || !validateCase(p.caseInput) {
		return p, "CASE_INVALID"
	}
	if jsoninput.Decode(beforeRaw, &p.before, int(MaxInputBytes)) != nil || !validatePolicy(p.before) {
		return p, "BEFORE_POLICY_INVALID"
	}
	if jsoninput.Decode(afterRaw, &p.after, int(MaxInputBytes)) != nil || !validatePolicy(p.after) {
		return p, "AFTER_POLICY_INVALID"
	}
	if p.before.Recipe.MaxBytes != p.after.Recipe.MaxBytes || p.before.RequiredAuthority != p.after.RequiredAuthority || p.before.MaxAgeSeconds != p.after.MaxAgeSeconds || p.before.ControlPlaneBudget != p.after.ControlPlaneBudget {
		return p, "COMMON_CONSTRAINT_MISMATCH"
	}
	control, err := machinerules.EvaluateEffects(controlFacts(), p.before.ControlPlaneBudget)
	if err != nil {
		return p, "HOST_UNAVAILABLE"
	}
	if !control.Admissible {
		return p, "CONTROL_PLANE_BUDGET_INVALID"
	}
	p.source, err = SourceIdentity()
	if err != nil {
		return p, "HOST_UNAVAILABLE"
	}
	p.base, err = policy.Simulate(baseInput(p.caseInput))
	if err != nil {
		return p, "HOST_UNAVAILABLE"
	}
	p.inputs = InputBindings{InputBinding{digest(caseRaw), canonicalDigest(p.caseInput)}, InputBinding{digest(beforeRaw), canonicalDigest(p.before)}, InputBinding{digest(afterRaw), canonicalDigest(p.after)}}
	p.permission = Permission{Eligible: true, Reason: "PROPOSED_PERMISSION_ELIGIBLE", ModeledHTTPStatus: 200}
	if !p.caseInput.Principal.Enabled {
		p.permission = Permission{Reason: "PROPOSED_PRINCIPAL_DISABLED", ModeledHTTPStatus: 401}
	} else if !p.caseInput.Principal.CanExecute {
		p.permission = Permission{Reason: "PROPOSED_EXECUTION_FORBIDDEN", ModeledHTTPStatus: 403}
	}
	return p, ""
}
