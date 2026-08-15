module github.com/syncplify/logverify

// 1.24 is the floor because HKDF entered the standard library there. Nothing in this module depends on
// anything outside the standard library, and nothing ever should: this tool exists to be read and rebuilt
// by people who have no reason to trust us, and every dependency is one more thing they have to audit
// before they can believe the output.
go 1.24.0
