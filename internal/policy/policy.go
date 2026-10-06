// Package policy transports inputs to compiled Gooo activities and records execution.
package policy

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"
)

//go:embed approval.gooo
var Source string

//go:embed generated.txt
var Generated string

//go:embed generation.json
var Generation json.RawMessage

type Request struct {
	Key       string `json:"key"`
	Requester string `json:"requester"`
	Team      string `json:"team"`
	Amount    int64  `json:"amount"`
	Submitted bool   `json:"submitted"`
}
type Reviewer struct {
	Key    string `json:"key"`
	Team   string `json:"team"`
	Active bool   `json:"active"`
}
type Rules struct {
	Limit          int64 `json:"limit"`
	SameTeam       bool  `json:"same_team"`
	ActiveReviewer bool  `json:"active_reviewer"`
	PreventSelf    bool  `json:"prevent_self"`
}
type Decision struct {
	Approved    bool   `json:"approved"`
	Reason      string `json:"reason"`
	AmountOK    bool   `json:"amount_ok"`
	TeamOK      bool   `json:"team_ok"`
	ReviewerOK  bool   `json:"reviewer_ok"`
	SelfOK      bool   `json:"self_ok"`
	SubmittedOK bool   `json:"submitted_ok"`
}
type Change struct {
	Changed       bool   `json:"changed"`
	Direction     string `json:"direction"`
	ReasonChanged bool   `json:"reason_changed"`
}
type Input struct {
	Request  Request  `json:"request"`
	Reviewer Reviewer `json:"reviewer"`
	Before   Rules    `json:"before"`
	After    Rules    `json:"after"`
}
type Result struct {
	Before Decision `json:"before"`
	After  Decision `json:"after"`
	Change Change   `json:"change"`
}
type Receipt struct {
	Schema          string `json:"schema"`
	ID              string `json:"id"`
	CreatedAt       string `json:"created_at"`
	SourceDigest    string `json:"source_sha256"`
	GeneratedDigest string `json:"generated_sha256"`
	CompilerSource  string `json:"compiler_source_sha"`
	Input           Input  `json:"input"`
	Result          Result `json:"result"`
	Scope           string `json:"scope"`
}

const Scope = "One request, two parameter sets, compiled Gooo activities; not a full-domain proof or a signed audit record."
const MaxAmount int64 = 9_000_000_000_000

func hash(b []byte) string { s := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(s[:]) }
func Validate(in Input) error {
	for _, s := range []string{in.Request.Key, in.Request.Requester, in.Request.Team, in.Reviewer.Key, in.Reviewer.Team} {
		if strings.TrimSpace(s) == "" || len(s) > 120 {
			return errors.New("이름·팀·요청 ID는 1~120바이트로 입력하세요")
		}
	}
	for _, n := range []int64{in.Request.Amount, in.Before.Limit, in.After.Limit} {
		if n < 0 || n > MaxAmount {
			return fmt.Errorf("금액은 0~%d 정수 원으로 입력하세요", MaxAmount)
		}
	}
	return nil
}
func Simulate(in Input) (Receipt, error) {
	if err := Validate(in); err != nil {
		return Receipt{}, err
	}
	before, err := evaluateNative(in.Request, in.Reviewer, in.Before)
	if err != nil {
		return Receipt{}, err
	}
	after, err := evaluateNative(in.Request, in.Reviewer, in.After)
	if err != nil {
		return Receipt{}, err
	}
	change, err := compareNative(before, after)
	if err != nil {
		return Receipt{}, err
	}
	var gen struct {
		Compiler struct {
			Source string `json:"compiler_source_sha"`
		} `json:"compiler"`
	}
	if err := json.Unmarshal(Generation, &gen); err != nil {
		return Receipt{}, err
	}
	r := Receipt{Schema: "policy-studio/execution/v1", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), SourceDigest: hash([]byte(Source)), GeneratedDigest: hash([]byte(Generated)), CompilerSource: gen.Compiler.Source, Input: in, Result: Result{before, after, change}, Scope: Scope}
	r.ID = receiptID(r)
	return r, nil
}
func receiptID(r Receipt) string { r.ID = ""; b, _ := json.Marshal(r); return hash(b) }
func Replay(r Receipt) (Receipt, error) {
	if r.Schema != "policy-studio/execution/v1" || r.Scope != Scope || r.ID != receiptID(r) {
		return Receipt{}, errors.New("기록 형식 또는 내용 해시가 일치하지 않습니다")
	}
	if r.SourceDigest != hash([]byte(Source)) || r.GeneratedDigest != hash([]byte(Generated)) {
		return Receipt{}, errors.New("현재 서버의 소스·생성 코드와 다른 기록입니다")
	}
	fresh, err := Simulate(r.Input)
	if err != nil {
		return Receipt{}, err
	}
	if r.CompilerSource != fresh.CompilerSource || !reflect.DeepEqual(r.Result, fresh.Result) {
		return Receipt{}, errors.New("재실행 결과 또는 컴파일러 출처가 일치하지 않습니다")
	}
	return fresh, nil
}
