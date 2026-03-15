from __future__ import annotations
from typing import Set, List


class ContextRegistry:
    def __init__(self) -> None:
        self._contexts: Set[str] = set()

    def register(self, context: str) -> None:
        self._contexts.add(context)

    def all(self) -> List[str]:
        return sorted(self._contexts)
