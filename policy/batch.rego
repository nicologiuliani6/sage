# Valutazione a blocchi: una sola chiamata a OPA per tutte le coppie (nodo, pacchetto).
# Input: {"items": [<input di sage.decision>, ...]}; output nello stesso ordine.
package sage.batch

import data.sage.decision

results := [r |
	some item in input.items
	a := decision.action with input as item
	s := decision.schedule with input as item
	r := {"action": a, "schedule": s}
]
