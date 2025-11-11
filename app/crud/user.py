"""
CRUD operations for User model
"""
from typing import Optional
from sqlalchemy.orm import Session
from app.models.user import User


class CRUDUser:
    """CRUD operations for User"""

    def get_by_keycloak_id(self, db: Session, keycloak_id: str) -> Optional[User]:
        """Get user by Keycloak ID"""
        return db.query(User).filter(User.keycloak_id == keycloak_id).first()

    def create_from_keycloak(
        self,
        db: Session,
        keycloak_id: str,
        username: str,
        email: str,
        full_name: Optional[str] = None
    ) -> User:
        """Create user from Keycloak data"""
        user = User(
            keycloak_id=keycloak_id,
            username=username,
            email=email,
            full_name=full_name,
            is_active=True
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user


user = CRUDUser()
