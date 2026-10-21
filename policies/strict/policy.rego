# Strict policy: every toxic flow blocks, unless data.exceptions covers it.
#
# Input: {"findings": [...]}, the scan's findings, each with id, rule, path (component names),
# the rule's fields (resource, sink, source, private_data, untrusted_input, egress), severity
# and project. Output: data.crosskill.decisions, one {id, action, reason} per finding.
package crosskill

decisions contains d if {
	some f in input.findings
	d := object.union({"id": f.id}, decision(f))
}

decision(f) := {"action": "ignore", "reason": e.reason} if {
	some e in data.exceptions
	covers(e, f)
} else := {"action": "block", "reason": sprintf("strict policy blocks every %s", [f.rule])}

# An exception covers a finding when every field it names matches: `component` is one of the
# components on the path, any other field is a glob over the finding's field of that name.
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
