"""Print ephemeral single-tenant development secrets. Do not check generated output into Git.

Equivalent to `recguard dev-env`.
"""
from recguard.__main__ import dev_env

dev_env('demo')
