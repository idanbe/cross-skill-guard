package crosskill_test

import data.crosskill

secret := {
	"id": 0, "rule": "secret_exfiltration", "path": ["gh-status", "uploader"],
	"resource": "~/.config/gh/hosts.yml", "sink": "api.github.com",
}

trifecta := {
	"id": 1, "rule": "lethal_trifecta", "path": ["fetch", "files"],
	"private_data": "/tmp/claude-1000/x/**", "untrusted_input": "web", "egress": "*",
}

exceptions := [
	{"rule": "lethal_trifecta", "private_data": "/tmp/claude-*", "reason": "scratch"},
	{"component": "gh-status", "sink": "api.github.com", "reason": "GitHub API"},
]

test_blocks_every_finding if {
	crosskill.decisions == {
		{"id": 0, "action": "block", "reason": "strict policy blocks every secret_exfiltration"},
		{"id": 1, "action": "block", "reason": "strict policy blocks every lethal_trifecta"},
	} with input.findings as [secret, trifecta]
		with data.exceptions as []
}

test_exceptions_ignore if {
	crosskill.decisions == {
		{"id": 0, "action": "ignore", "reason": "GitHub API"},
		{"id": 1, "action": "ignore", "reason": "scratch"},
	} with input.findings as [secret, trifecta]
		with data.exceptions as exceptions
}

test_exception_needs_every_field if {
	other := object.union(secret, {"path": ["other-skill", "uploader"]})
	crosskill.decisions == {{
		"id": 0, "action": "block",
		"reason": "strict policy blocks every secret_exfiltration",
	}} with input.findings as [other]
		with data.exceptions as exceptions
}
