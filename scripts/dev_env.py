"""Print ephemeral single-tenant development secrets. Do not check generated output into Git.

Equivalent to `recguard dev-env`; works from a plain checkout without installing.
    python3 scripts/dev_env.py              # export lines for your shell
    python3 scripts/dev_env.py --env-file .env   # file for `docker compose up`
"""
import importlib.util, pathlib, sys

# Load the stdlib-only CLI module directly so this runs before `pip install` (no pydantic needed).
spec = importlib.util.spec_from_file_location("recguard_cli", pathlib.Path(__file__).resolve().parent.parent / "recguard" / "__main__.py")
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)
cli.main(['dev-env', *sys.argv[1:]])
