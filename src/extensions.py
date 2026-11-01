"""Flask extensions shared by HashGuard application instances."""

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect


csrf = CSRFProtect()
limiter = Limiter(get_remote_address, default_limits=[])
