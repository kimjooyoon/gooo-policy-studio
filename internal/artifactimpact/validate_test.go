package artifactimpact

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kimjooyoon/gooo-policy-studio/internal/admission"
	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactpreflight"
)

func TestInvalidConfigurationBeforeReservationOrArtifactAcquisition(t *testing.T) {
	cases := []struct {
		name, code string
		alter      func(Paths, Case, admission.ArtifactPolicy)
	}{
		{"caseunknown", "CASE_INVALID", func(p Paths, c Case, a admission.ArtifactPolicy) {
			raw, _ := os.ReadFile(p.Case)
			raw = append(raw[:len(raw)-1], []byte(`,"caller_time":1}`)...)
			if err := os.WriteFile(p.Case, raw, 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"casenull", "CASE_INVALID", func(p Paths, c Case, a admission.ArtifactPolicy) {
			raw, _ := os.ReadFile(p.Case)
			raw = []byte(strings.Replace(string(raw), `"enabled":true`, `"enabled":null`, 1))
			if err := os.WriteFile(p.Case, raw, 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"casemissing", "CASE_INVALID", func(p Paths, c Case, a admission.ArtifactPolicy) {
			raw, _ := os.ReadFile(p.Case)
			raw = []byte(strings.Replace(string(raw), `"enabled":true,`, "", 1))
			if err := os.WriteFile(p.Case, raw, 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"casealias", "CASE_INVALID", func(p Paths, c Case, a admission.ArtifactPolicy) {
			raw, _ := os.ReadFile(p.Case)
			raw = []byte(strings.Replace(string(raw), `"schema"`, `"Schema"`, 1))
			if err := os.WriteFile(p.Case, raw, 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"caseduplicate", "CASE_INVALID", func(p Paths, c Case, a admission.ArtifactPolicy) {
			raw, _ := os.ReadFile(p.Case)
			raw = append([]byte(`{"schema":"shadow",`), raw[1:]...)
			if err := os.WriteFile(p.Case, raw, 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"casepermissive", "CASE_FILE_INVALID", func(p Paths, c Case, a admission.ArtifactPolicy) {
			if err := os.Chmod(p.Case, 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"casecontrols", "CASE_INVALID", func(p Paths, c Case, a admission.ArtifactPolicy) {
			c.Principal.Key = "private\nidentity"
			privateJSON(t, p.Case, c)
		}},
		{"relativeartifact", "CASE_INVALID", func(p Paths, c Case, a admission.ArtifactPolicy) {
			c.Artifact.Path = "artifact.json"
			privateJSON(t, p.Case, c)
		}},
		{"zerodeadline", "CASE_INVALID", func(p Paths, c Case, a admission.ArtifactPolicy) {
			c.Artifact.DeadlineUnix = 0
			privateJSON(t, p.Case, c)
		}},
		{"unknownproducer", "AFTER_POLICY_INVALID", func(p Paths, c Case, a admission.ArtifactPolicy) {
			a.Recipe.ProducerID = "caller/pass"
			privateJSON(t, p.After, a)
		}},
		{"unknownverifier", "AFTER_POLICY_INVALID", func(p Paths, c Case, a admission.ArtifactPolicy) {
			a.Recipe.Claims[0].Verifier = "caller/pass"
			privateJSON(t, p.After, a)
		}},
		{"authorityunsupported", "AFTER_POLICY_INVALID", func(p Paths, c Case, a admission.ArtifactPolicy) {
			a.RequiredAuthority = "theorem"
			privateJSON(t, p.After, a)
		}},
		{"maxbytes", "COMMON_CONSTRAINT_MISMATCH", func(p Paths, c Case, a admission.ArtifactPolicy) { a.Recipe.MaxBytes = 100; privateJSON(t, p.After, a) }},
		{"maxage", "COMMON_CONSTRAINT_MISMATCH", func(p Paths, c Case, a admission.ArtifactPolicy) { a.MaxAgeSeconds++; privateJSON(t, p.After, a) }},
		{"authority", "COMMON_CONSTRAINT_MISMATCH", func(p Paths, c Case, a admission.ArtifactPolicy) {
			a.RequiredAuthority = "unit"
			privateJSON(t, p.After, a)
		}},
		{"controlmismatch", "COMMON_CONSTRAINT_MISMATCH", func(p Paths, c Case, a admission.ArtifactPolicy) {
			a.ControlPlaneBudget.AllowNetwork = true
			privateJSON(t, p.After, a)
		}},
		{"controldenial", "CONTROL_PLANE_BUDGET_INVALID", func(p Paths, c Case, a admission.ArtifactPolicy) {
			a.ControlPlaneBudget.AllowFilesystem = false
			privateJSON(t, p.Before, a)
			privateJSON(t, p.After, a)
		}},
		{"policyflag", "AFTER_POLICY_INVALID", func(p Paths, c Case, a admission.ArtifactPolicy) {
			raw, _ := os.ReadFile(p.After)
			raw = append(raw[:len(raw)-1], []byte(`,"provider_verified":true}`)...)
			if err := os.WriteFile(p.After, raw, 0600); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			paths, c, p := fixture(t, 1)
			tc.alter(paths, c, p)
			reads := 0
			s, exit := compareFiles(paths, dependencies{readArtifact: func(artifactpreflight.Requirement, int64) (artifactpreflight.Acquisition, error) {
				reads++
				return artifactpreflight.Acquisition{}, errors.New("PRIVATE ERROR")
			}, now: func() time.Time { t.Fatal("clock before validation"); return time.Time{} }})
			if exit != 2 || s.Code != tc.code || s.ReportSaved || reads != 0 {
				t.Fatalf("wrong static invalid result %+v", s)
			}
			if _, err := os.Lstat(paths.Report); !os.IsNotExist(err) {
				t.Fatal("invalid config reserved output")
			}
		})
	}
}

func TestReservationFailsBeforeAcquisitionAndHostFailuresRetainReservation(t *testing.T) {
	paths, c, _ := fixture(t, 1)
	if err := os.WriteFile(paths.Report, []byte("original private report"), 0600); err != nil {
		t.Fatal(err)
	}
	reads := 0
	deps := dependencies{readArtifact: func(artifactpreflight.Requirement, int64) (artifactpreflight.Acquisition, error) {
		reads++
		return artifactpreflight.Acquisition{}, errors.New("PRIVATE ERROR")
	}, now: func() time.Time { return time.Unix(testUnix, 0) }}
	s, exit := compareFiles(paths, deps)
	raw, _ := os.ReadFile(paths.Report)
	if exit != 2 || s.Code != "REPORT_FILE_UNAVAILABLE" || reads != 0 || string(raw) != "original private report" {
		t.Fatal("existing report reached artifact or overwritten")
	}
	paths.Report = c.Artifact.Path
	s, exit = compareFiles(paths, deps)
	if exit != 2 || s.Code != "REPORT_FILE_UNAVAILABLE" || reads != 0 {
		t.Fatal("artifact alias reached capture")
	}
	paths, c, _ = fixture(t, 1)
	s, exit = compareFiles(paths, deps)
	raw, err := os.ReadFile(paths.Report)
	if exit != 2 || s.Code != "ACQUISITION_SOURCE_INVALID" || reads != 1 || err != nil || len(raw) != 0 || s.ReportSaved {
		t.Fatal("host failure did not retain incomplete reservation")
	}
	paths, _, _ = fixture(t, 1)
	s, exit = compareFiles(paths, dependencies{artifactpreflight.ReadArtifact, func() time.Time { return time.Unix(0, 0) }})
	raw, err = os.ReadFile(paths.Report)
	if exit != 2 || s.Code != "HOST_CLOCK_INVALID" || err != nil || len(raw) != 0 {
		t.Fatal("bad host clock presented complete report")
	}
}
