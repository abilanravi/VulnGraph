"""Server-side role checks. Frontend hiding of buttons is UX only — every enforcement point
that matters lives here and is applied as a FastAPI dependency on the route itself.
"""

from fastapi import Depends, HTTPException, status

from app.api.deps import get_current_active_user
from app.db.models import User, UserRole


def require_roles(*roles: UserRole):
    """Returns a dependency that 403s unless the current user has one of `roles`."""

    def _check(current_user: User = Depends(get_current_active_user)) -> User:
        if current_user.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return current_user

    return _check


require_admin = require_roles(UserRole.ADMIN)
require_scan_access = require_roles(UserRole.ADMIN, UserRole.DEVELOPER)
