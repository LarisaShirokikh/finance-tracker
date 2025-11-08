"""
Category Pydantic schemas for request/response validation
"""
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class CategoryBase(BaseModel):
    """Base schema with common fields"""
    name: str = Field(..., min_length=1, max_length=100, description="Category name")
    type: str = Field(..., description="Category type: income or expense")
    description: Optional[str] = Field(None, max_length=500, description="Category description")
    color: Optional[str] = Field(None, pattern="^#[0-9A-Fa-f]{6}$", description="Color in hex format")
    icon: Optional[str] = Field(None, max_length=50, description="Icon name or emoji")
    is_default: bool = Field(default=False, description="Is this a default category")

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        """Validate category type"""
        if v not in ["income", "expense"]:
            raise ValueError("Type must be 'income' or 'expense'")
        return v


class CategoryCreate(CategoryBase):
    """Schema for creating a new category"""
    pass


class CategoryUpdate(BaseModel):
    """Schema for updating a category (all fields optional)"""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    type: Optional[str] = None
    description: Optional[str] = Field(None, max_length=500)
    color: Optional[str] = Field(None, pattern="^#[0-9A-Fa-f]{6}$")
    icon: Optional[str] = Field(None, max_length=50)
    is_default: Optional[bool] = None

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: Optional[str]) -> Optional[str]:
        """Validate category type"""
        if v is not None and v not in ["income", "expense"]:
            raise ValueError("Type must be 'income' or 'expense'")
        return v


class CategoryInDB(CategoryBase):
    """Schema for category from database"""
    id: int
    user_id: int
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class CategoryResponse(CategoryInDB):
    """Schema for API response"""
    pass
