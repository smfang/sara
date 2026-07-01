"""
Export the trained LoRA adapter and expose SaraTinkerBackend.

# A.3a-full: replace stub with:
#   from tinker_cookbook.weights import download, merge_tinker_adapter_to_hf_model
#   adapter_path = download(checkpoint_id, local_dir="adapters/sara-dao")
#   merge_tinker_adapter_to_hf_model(adapter_path, cfg.base_model, output_dir)
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

_BACKEND_ENV = "SARA_BACKEND"


class SaraTinkerBackend:
    """
    Drop-in backend for SaraBoxClassifier when SARA_BACKEND=tinker_lora.

    Wire:
        import os; os.environ["SARA_BACKEND"] = "tinker_lora"
        from src.agent_rl.tinker_spike.export import SaraTinkerBackend
        classifier = SaraTinkerBackend.from_checkpoint("step-400")
    """

    def __init__(self, adapter_path: str) -> None:
        self._adapter_path = adapter_path
        # A.3a-full: load merged HF model here

    @classmethod
    def from_checkpoint(cls, checkpoint_id: str, output_dir: str = "adapters/sara-dao") -> "SaraTinkerBackend":
        adapter_path = _download_adapter(checkpoint_id, output_dir)
        return cls(adapter_path)

    def classify(self, prompt: str) -> dict:
        # A.3a-full: run inference on the merged model
        raise NotImplementedError(
            "SaraTinkerBackend.classify() requires a real adapter. "
            "Run training first, then export."
        )


def _download_adapter(checkpoint_id: str, output_dir: str) -> str:
    """
    Download LoRA adapter from Tinker and merge into HF model.

    # A.3a-full:
    #   from tinker_cookbook.weights import download, merge_tinker_adapter_to_hf_model
    #   local = download(checkpoint_id, local_dir=output_dir)
    #   return merge_tinker_adapter_to_hf_model(local, base_model, output_dir)
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    stub_path = os.path.join(output_dir, f"{checkpoint_id}.stub")
    Path(stub_path).touch()
    logger.info("adapter stub written to %s (A.3a-full: real download)", stub_path)
    return stub_path
