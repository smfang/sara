"""
Spec-named boundary test (CLAUDE.md invariant: `tests/test_boundary.py` must
fail if src/safety/ or src/sarabox/ imports agents.sheila internals).

The actual assertions live in `tests/test_two_agent_boundary.py`; this thin
shim re-exports them under the spec-cited filename so the invariant path in
CLAUDE.md and the A-prompts resolves. Do not add logic here — edit the real
module instead.
"""

from tests.test_two_agent_boundary import (  # noqa: F401
    test_monitor_does_not_import_sheila_judge,
    test_monitor_does_not_import_sheila_red_team,
    test_sheila_api_module_exists,
    test_sheila_judge_instantiates_local_without_a2a_url,
    test_sheila_judge_uses_a2a_when_url_set,
    test_sheila_verdict_has_required_fields,
    test_sheila_verdict_instantiates_correctly,
)
