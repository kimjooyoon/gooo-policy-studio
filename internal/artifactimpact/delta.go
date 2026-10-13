package artifactimpact

import (
	"reflect"

	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactpreflight"
	"github.com/kimjooyoon/gooo-policy-studio/internal/machinerules"
)

type recipeMeaning struct {
	Schema, ProducerID, ArtifactSchema string
	MaxBytes                           int64
	Fields                             map[string]string
	Claims                             map[string]artifactpreflight.Claim
}

func meaning(r artifactpreflight.Recipe) recipeMeaning {
	m := recipeMeaning{r.Schema, r.ProducerID, r.ArtifactSchema, r.MaxBytes, map[string]string{}, map[string]artifactpreflight.Claim{}}
	for _, f := range r.Fields {
		m.Fields[f.Name] = f.Type
	}
	for _, c := range r.Claims {
		m.Claims[c.ID] = c
	}
	return m
}
func delta(before, after Side) Delta {
	b, a := before.Context.Policy, after.Context.Policy
	d := Delta{Direction: "unchanged", Added: []string{}, Removed: []string{}, Changed: []ClaimChange{}, PolicyIdentityChanged: b.ID != a.ID || b.Revision != a.Revision,
		RecipeConfigurationChanged: !reflect.DeepEqual(meaning(b.Recipe), meaning(a.Recipe)), ApprovalBudgetChanged: b.ApprovalBudget != a.ApprovalBudget,
		ApprovalChecksChanged: before.ProposedApproval.Decision != after.ProposedApproval.Decision, ControlPlaneChecksChanged: before.ProposedControlPlane.Decision != after.ProposedControlPlane.Decision}
	if !before.WouldAdmit && after.WouldAdmit {
		d.Direction = "newly_allowed"
	} else if before.WouldAdmit && !after.WouldAdmit {
		d.Direction = "newly_denied"
	}
	bm, am := meaning(b.Recipe), meaning(a.Recipe)
	bOrder, aOrder := make([]string, 0, len(b.Recipe.Claims)), make([]string, 0, len(a.Recipe.Claims))
	bObs, aObs := map[string]artifactpreflight.ClaimObservation{}, map[string]artifactpreflight.ClaimObservation{}
	bEvidence, aEvidence := map[string]machinerules.EvidenceDecision{}, map[string]machinerules.EvidenceDecision{}
	for _, o := range before.Producer.Observations {
		bObs[o.ClaimID] = o
	}
	for _, o := range after.Producer.Observations {
		aObs[o.ClaimID] = o
	}
	for _, e := range before.Evidence {
		bEvidence[e.ClaimID] = e.Decision
	}
	for _, e := range after.Evidence {
		aEvidence[e.ClaimID] = e.Decision
	}
	for _, c := range a.Recipe.Claims {
		if _, exists := bm.Claims[c.ID]; !exists {
			d.Added = append(d.Added, c.ID)
		} else {
			aOrder = append(aOrder, c.ID)
		}
	}
	for _, c := range b.Recipe.Claims {
		next, exists := am.Claims[c.ID]
		if !exists {
			d.Removed = append(d.Removed, c.ID)
			continue
		}
		bOrder = append(bOrder, c.ID)
		oldObs, newObs := bObs[c.ID], aObs[c.ID]
		change := ClaimChange{ClaimID: c.ID, PredicateChanged: c.Verifier != next.Verifier || c.Field != next.Field || c.Expected != next.Expected,
			ArtifactSchemaChanged: b.Recipe.ArtifactSchema != a.Recipe.ArtifactSchema, FieldTypeChanged: bm.Fields[c.Field] != am.Fields[next.Field],
			StatusChanged: oldObs.Status != newObs.Status, ReasonChanged: oldObs.Reason != newObs.Reason, ActualChanged: oldObs.Actual != newObs.Actual, EvidenceDecisionChanged: bEvidence[c.ID] != aEvidence[c.ID]}
		if change.PredicateChanged || change.ArtifactSchemaChanged || change.FieldTypeChanged || change.StatusChanged || change.ReasonChanged || change.ActualChanged || change.EvidenceDecisionChanged {
			d.Changed = append(d.Changed, change)
		}
	}
	d.ClaimOrderChanged = !reflect.DeepEqual(bOrder, aOrder)
	return d
}
