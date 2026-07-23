"""Neutral A2A (Agent-to-Agent) protocol primitives shared by Sara and Sheila.

This package is agent-agnostic: it carries the A2A v0.3.0 wire contract (Agent
Card signing/verification, JSON-RPC 2.0 envelope + error codes, Task/Artifact
serialization) so BOTH agents speak identical, conformant A2A without importing
each other. Sara importing this is NOT a boundary violation — it is shared
protocol code, not a Sheila internal.
"""
