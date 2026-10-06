"""Configuração do app. Tudo que muda entre produção e testes fica aqui."""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


@dataclass
class Settings:
    db_path: Path = Path("bank.db")
    keys_dir: Path = Path("secrets")
    secure_cookies: bool = True  # cookie só trafega por HTTPS
    clock: Callable[[], float] = time.time  # injetável para os testes
    max_failed_attempts: int = 5
    lock_seconds: int = 15 * 60
    session_idle_seconds: int = 15 * 60

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            db_path=Path(os.environ.get("BANK_DB", "bank.db")),
            keys_dir=Path(os.environ.get("BANK_KEYS_DIR", "secrets")),
        )

    def now(self) -> int:
        return int(self.clock())
