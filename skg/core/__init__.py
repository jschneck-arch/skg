# skg.core
# Lazy submodule exposure: allows mock.patch("skg.core.daemon.X") to work
# without pulling in uvicorn/heavy daemon dependencies at import time.
def __getattr__(name: str):
    import importlib
    try:
        return importlib.import_module(f"skg.core.{name}")
    except ModuleNotFoundError:
        raise AttributeError(f"module 'skg.core' has no attribute {name!r}") from None
