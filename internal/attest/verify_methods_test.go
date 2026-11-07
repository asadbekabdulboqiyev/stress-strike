package attest

import "testing"

func TestCheckErrorMethods(t *testing.T) {
	e := CheckError{Worker: "w1", Check: "merkle", Index: ptrInt64(3), Detail: "hash mismatch"}
	if got := e.Error(); got != "w1/merkle (leaf 3): hash mismatch" {
		t.Errorf("CheckError.Error() = %q", got)
	}
	if got := e.String(); got != e.Error() {
		t.Errorf("CheckError.String() = %q, want Error() %q", got, e.Error())
	}

	e2 := CheckError{Check: "format", Detail: "bad version"}
	if got := e2.Error(); got != "format: bad version" {
		t.Errorf("CheckError.Error() = %q", got)
	}
}

func TestVerifyResultOKAndErrors(t *testing.T) {
	r := VerifyResult{Valid: true}
	if !r.OK() {
		t.Error("VerifyResult.OK() = false, want true")
	}
	if _, ok := r.FirstError(); ok {
		t.Error("FirstError() on valid result = ok, want false")
	}
	if got := r.ErrorLines(); len(got) != 0 {
		t.Errorf("ErrorLines() = %v, want empty", got)
	}

	r = VerifyResult{Valid: false, Errors: []CheckError{{Check: "c1", Detail: "d1"}, {Check: "c2", Detail: "d2"}}}
	if r.OK() {
		t.Error("VerifyResult.OK() = true, want false")
	}
	e, ok := r.FirstError()
	if !ok || e.Check != "c1" {
		t.Errorf("FirstError() = %v, %v, want c1 true", e, ok)
	}
	lines := r.ErrorLines()
	if len(lines) != 2 || lines[0] != "c1: d1" || lines[1] != "c2: d2" {
		t.Errorf("ErrorLines() = %v", lines)
	}
}

func ptrInt64(v int64) *int64 { return &v }
