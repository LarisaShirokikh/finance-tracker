"""
User model
"""
from typing import List, TYPE_CHECKING

from sqlalchemy import String, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.category import Category
    from app.models.transaction import Transaction


class User(Base, TimestampMixin):
    """
    User model

    Linked to Keycloak user via keycloak_id
    """
    __tablename__ = "users"

    # Primary key
    id: Mapped[int] = mapped_column(primary_key=True, index=True)

    # Keycloak integration
    keycloak_id: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
        comment="UUID from Keycloak"
    )

    # User info (synced from Keycloak)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, index=True)

    # Optional fields
    full_name: Mapped[str | None] = mapped_column(String(255))

    # Soft delete
    is_active: Mapped[bool] = mapped_column(default=True)

    # Relationships
    categories: Mapped[List["Category"]] = relationship(
        "Category",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    transactions: Mapped[List["Transaction"]] = relationship(
        "Transaction",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    # Indexes
    __table_args__ = (
        Index("idx_user_keycloak_id", "keycloak_id"),
        Index("idx_user_email", "email"),
    )

    def __repr__(self) -> str:
        return f"<User(id={self.id}, username={self.username}, email={self.email})>"
