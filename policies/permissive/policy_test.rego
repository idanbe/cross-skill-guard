package crosskill_test

import data.crosskill

action(f) := d.action if {
	some d in crosskill.decisions with input.findings as [f] with data.exceptions as []
}

test_untrusted_to_execution_blocks if {
	action({"id": 0, "rule": "untrusted_to_execution", "path": ["a", "b"], "source": "web", "sink": "bash"}) == "block"
}

test_secret_to_any_host_blocks if {
	action({"id": 0, "rule": "secret_exfiltration", "path": ["a"], "resource": ".env", "sink": "*"}) == "block"
}

test_secret_to_named_host_warns if {
	action({"id": 0, "rule": "secret_exfiltration", "path": ["a"], "resource": ".env", "sink": "api.github.com"}) == "warn"
}

test_trifecta_warns if {
	action({"id": 0, "rule": "lethal_trifecta", "path": ["a"], "private_data": "~/work", "untrusted_input": "web", "egress": "*"}) == "warn"
}

test_exception_wins if {
	f := {"id": 0, "rule": "untrusted_to_execution", "path": ["a"], "source": "web", "sink": "bash"}
	crosskill.decisions == {{"id": 0, "action": "ignore", "reason": "ok"}} with input.findings as [f]
		with data.exceptions as [{"component": "a", "reason": "ok"}]
}
