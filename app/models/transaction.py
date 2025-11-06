"""
Transaction model for financial transactions
"""
from typing import TYPE_CHECKING
from datetime import date
from decimal import Decimal

from sqlalchemy import String, ForeignKey, Index, Numeric, Date
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin
from app.models.category import CategoryType

if TYPE_CHECKING:
    from app.models.user import User
    from app.models.category import Category


class Transaction(Base, TimestampMixin):
    """
    Transaction model

    Represents a financial transaction (income or expense)
    """
    __tablename__ = "transactions"

    # Primary key
    id: Mapped[int] = mapped_column(primary_key=True, index=True)

    # Transaction details
    amount: Mapped[Decimal] = mapped_column(
        Numeric(precision=12, scale=2),
        nullable=False,
        comment="Transaction amount (always positive)"
    )

    type: Mapped[CategoryType] = mapped_column(
        nullable=False,
        comment="Income or Expense"
    )

    description: Mapped[str | None] = mapped_column(
        String(500),
        comment="Optional transaction description"
    )

    # Date
    transaction_date: Mapped[date] = mapped_column(
        Date,
        nullable=False,
        index=True,
        comment="Date of transaction"
    )

    # Foreign keys
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    category_id: Mapped[int] = mapped_column(
        ForeignKey("categories.id", ondelete="RESTRICT"),
        nullable=False,
        index=True
    )

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="transactions")
    category: Mapped["Category"] = relationship("Category", back_populates="transactions")

    # Indexes for common queries
    __table_args__ = (
        Index("idx_transaction_user_date", "user_id", "transaction_date"),
        Index("idx_transaction_user_category", "user_id", "category_id"),
        Index("idx_transaction_type", "type"),
    )

    def __repr__(self) -> str:
        return (
            f"<Transaction(id={self.id}, type={self.type}, "
            f"amount={self.amount}, date={self.transaction_date})>"
        )
