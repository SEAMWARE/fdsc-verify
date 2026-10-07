"""Importing this package registers every check, in report order.

Order matters: the cheapest and most explanatory checks come first, so that a
broken deployment produces its real diagnosis at the top of the output rather
than fifteen lines down. `static` leads because a misconfiguration explains
itself, while its runtime symptoms are downstream and generic.
"""

from . import profile  # noqa: F401  - "what am I looking at" comes first of all
from . import components  # noqa: F401  - what this deployment is, before what it does
from . import static  # noqa: F401
from . import keycloak  # noqa: F401  - the issuer's own configuration
from . import identity  # noqa: F401
from . import certs  # noqa: F401
from . import infra  # noqa: F401
from . import broker  # noqa: F401
from . import dashboard  # noqa: F401
from . import marketplace  # noqa: F401
from . import contractmanagement  # noqa: F401
from . import centralmp  # noqa: F401  - the provider that publishes elsewhere
from . import fiware  # noqa: F401
from . import peers  # noqa: F401
from . import flows  # noqa: F401
