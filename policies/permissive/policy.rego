# Permissive policy: block only flows that reach any host or run arbitrary code; warn on the
# rest. data.exceptions still wins. Same input and output as strict.rego.
package crosskill

decisions contains d if {
	some f in input.findings
	d := object.union({"id": f.id}, decision(f))
}

decision(f) := {"action": "ignore", "reason": e.reason} if {
	some e in data.exceptions
	covers(e, f)
} else := {"action": "block", "reason": "untrusted input can run arbitrary code"} if {
	f.rule == "untrusted_to_execution"
} else := {"action": "block", "reason": "a secret can reach any host"} if {
	f.rule == "secret_exfiltration"
	f.sink == "*"
} else := {"action": "warn", "reason": sprintf("%s to a named host or of non-secret data: review it", [f.rule])}

covers(e, f) if {
	every k, v in object.remove(e, {"reason"}) {
		matches(k, v, f)
	}
}

matches("component", v, f) if v in f.path

matches(k, v, f) if {
	k != "component"
	glob.match(v, null, f[k])
}
