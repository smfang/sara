"""
Sara DAO RL spike — Light one-sided RLVR fine-tune of Sara against a frozen Sheila judge.

**Hosted training notice:** When wired to real Tinker, training data and gradients leave this
perimeter to Thinking Machines' GPUs. Acceptable for the DAO/insurance spike because only
SHA3-256(prompt) is persisted locally (raw attack text is never logged at INFO+). NOT the
production path for federated/private-org training — that is TEE + DP-SGD (A.5 / PRD-SAFE).

Today (MVP): Tinker APIs are stubbed. Real swap paths:
  - A.3a-full: wire TinkerStub → real tinker.ServiceClient once TINKER_API_KEY is set.
  - A.3a-trl:  swap TinkerStub → TRL GRPOTrainer (torch/peft/trl are installed).
"""
