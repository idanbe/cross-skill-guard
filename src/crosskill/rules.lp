% Input from the extractors (see docs/facts.md):
%   grant(G, C, Kind, Arg)   component C has capability Kind on Arg; G is the grant id
%   denied(G)                a settings.json deny rule removes grant G
%   component(C). secret(R). private(R). arbitrary(X).
#const maxlen = 8.

% A deny rule wins over any allow.
active(G) :- grant(G, _, _, _), not denied(G).

% Data moves along grants: a resource into the component that reads it, a component into
% the resource it writes.
step(r(R), c(C), G) :- grant(G, C, reads, R), active(G).
step(c(C), r(R), G) :- grant(G, C, writes, R), active(G).

% flow(Kind, Origin, Node, Path, Len, Ctx): data of Kind from Origin reaches Node.
% Path holds the grant ids used, newest first: p(G, p(G', ... nil)).
flow(secret, S, r(S), nil, 0, 0) :- secret(S).
flow(private, D, r(D), nil, 0, 0) :- private(D), not secret(D).
flow(untrusted, U, c(C), p(G, nil), 1, 0) :- grant(G, C, untrusted, U), active(G).
flow(K, O, Y, p(G, P), L+1, X) :- flow(K, O, N, P, L, X), step(N, Y, G), L < maxlen.
% All components share the agent's context, so data in one reaches every other.
% Ctx = 1 once a path has used that hop; one hop is always enough.
flow(K, O, c(C2), P, L+1, 1) :- flow(K, O, c(C), P, L, 0), component(C2), C2 != C, L < maxlen.

secret_exfiltration(S, D, p(G, P)) :-
    flow(secret, S, c(C), P, _, _), grant(G, C, egress, D), active(G).
untrusted_to_execution(U, X, p(G, P)) :-
    flow(untrusted, U, c(C), P, _, _), grant(G, C, executes, X), active(G), arbitrary(X).
% Untrusted input can steer the agent, and private (non-secret) data reaches a sink.
lethal_trifecta(D, U, E, GU, p(G, P)) :-
    flow(private, D, c(C), P, _, _), grant(G, C, egress, E), active(G),
    grant(GU, _, untrusted, U), active(GU).

#show secret_exfiltration/3.
#show untrusted_to_execution/3.
#show lethal_trifecta/5.
