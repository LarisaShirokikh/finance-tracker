"""
Category model for income/expense categorization
"""
from typing import List, TYPE_CHECKING
from enum import Enum

from sqlalchemy import String, ForeignKey, Index, Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.user import User
    from app.models.transaction import Transaction


class CategoryType(str, Enum):
    """Category type enum"""
    INCOME = "income"
    EXPENSE = "expense"


class Category(Base, TimestampMixin):
    """
    Category model

    Categories can be:
    - User-specific (created by user)
    - Default/system (is_default=True, user_id=None)
    """
    __tablename__ = "categories"

    # Primary key
    id: Mapped[int] = mapped_column(primary_key=True, index=True)

    # Category info
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    type: Mapped[CategoryType] = mapped_column(SQLEnum(CategoryType), nullable=False)

    # Visual customization
    color: Mapped[str | None] = mapped_column(
        String(7),
        default="#6366f1",
        comment="Hex color code"
    )
    icon: Mapped[str | None] = mapped_column(
        String(50),
        default="📁",
        comment="Emoji or icon name"
    )

    # Ownership
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True
    )

    # System categories (shared by all users)
    is_default: Mapped[bool] = mapped_column(
        default=False,
        comment="System/default category visible to all users"
    )

    # Soft delete
    is_active: Mapped[bool] = mapped_column(default=True)

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="categories")

    transactions: Mapped[List["Transaction"]] = relationship(
        "Transaction",
        back_populates="category"
    )

    # Indexes
    __table_args__ = (
        Index("idx_category_user_id", "user_id"),
        Index("idx_category_type", "type"),
        Index("idx_category_is_default", "is_default"),
    )

    def __repr__(self) -> str:
        return f"<Category(id={self.id}, name={self.name}, type={self.type})>"
