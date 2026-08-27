from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from functools import wraps
import threading
from typing import ParamSpec, TypeVar

_AUTHORITY_FENCE = threading.RLock()

P = ParamSpec("P")
R = TypeVar("R")


@contextmanager
def authority_fence() -> Iterator[None]:
    """Serialize local authority mutations with relay dispatch admission."""
    with _AUTHORITY_FENCE:
        yield


def serialized_authority_mutation(func: Callable[P, R]) -> Callable[P, R]:
    @wraps(func)
    def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
        with authority_fence():
            return func(*args, **kwargs)

    return wrapped
