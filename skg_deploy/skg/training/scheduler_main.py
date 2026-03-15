"""Entry point for systemd skg-train.service."""
import logging
import json
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

log = logging.getLogger("skg.training.main")

if __name__ == "__main__":
    from skg.training.scheduler import run
    result = run()
    log.info(f"scheduler result: {json.dumps(result, default=str)}")
    # Exit 0 always — don't fail the service on skip/no-corpus
    sys.exit(0)
