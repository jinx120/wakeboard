import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    poll_interval: int = 30
    wake_timeout: int = 300
    guest_timeout: int = 120

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(data_dir=Path(os.environ.get("WAKEBOARD_DATA", "/data")))
