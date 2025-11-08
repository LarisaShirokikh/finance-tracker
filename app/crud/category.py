"""
CRUD operations for Category model
"""
from typing import List, Optional

from sqlalchemy import and_
from sqlalchemy.orm import Session

from app.models.category import Category
from app.schemas.category import CategoryCreate, CategoryUpdate


class CRUDCategory:
    """CRUD operations for Category"""

    def get(self, db: Session, category_id: int, user_id: int) -> Optional[Category]:
        """Get category by ID for specific user"""
        return db.query(Category).filter(
            and_(
                Category.id == category_id,
                Category.user_id == user_id
            )
        ).first()

    def get_multi(
        self,
        db: Session,
        user_id: int,
        skip: int = 0,
        limit: int = 100,
        category_type: Optional[str] = None
    ) -> List[Category]:
        """Get multiple categories for user with optional filtering"""
        query = db.query(Category).filter(Category.user_id == user_id)

        if category_type:
            query = query.filter(Category.type == category_type)

        return query.offset(skip).limit(limit).all()

    def create(self, db: Session, obj_in: CategoryCreate, user_id: int) -> Category:
        """Create new category for user"""
        db_obj = Category(
            **obj_in.model_dump(),
            user_id=user_id
        )
        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)
        return db_obj

    def update(
        self,
        db: Session,
        db_obj: Category,
        obj_in: CategoryUpdate
    ) -> Category:
        """Update category"""
        update_data = obj_in.model_dump(exclude_unset=True)

        for field, value in update_data.items():
            setattr(db_obj, field, value)

        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)
        return db_obj

    def delete(self, db: Session, category_id: int, user_id: int) -> Optional[Category]:
        """Delete category"""
        db_obj = self.get(db=db, category_id=category_id, user_id=user_id)
        if db_obj:
            db.delete(db_obj)
            db.commit()
        return db_obj

    def get_by_name(
        self,
        db: Session,
        name: str,
        user_id: int
    ) -> Optional[Category]:
        """Get category by name for specific user"""
        return db.query(Category).filter(
            and_(
                Category.name == name,
                Category.user_id == user_id
            )
        ).first()


# Create instance
category = CRUDCategory()
