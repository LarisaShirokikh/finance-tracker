"""
Category API endpoints
"""
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.crud import category as crud_category
from app.crud import user as crud_user
from app.db.session import get_db
from app.models.user import User
from app.schemas.category import CategoryCreate, CategoryResponse, CategoryUpdate

router = APIRouter()


@router.get("/", response_model=List[CategoryResponse])
def get_categories(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=100, description="Number of records to return"),
    type: Optional[str] = Query(None, description="Filter by type: income or expense")
):
    """
    Get all categories for current user

    - **skip**: Number of records to skip (pagination)
    - **limit**: Maximum number of records to return
    - **type**: Optional filter by category type
    """
    categories = crud_category.get_multi(
        db=db,
        user_id=current_user.id,
        skip=skip,
        limit=limit,
        category_type=type
    )
    return categories


@router.get("/{category_id}", response_model=CategoryResponse)
def get_category(
    category_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get specific category by ID
    """
    category = crud_category.get(db=db, category_id=category_id, user_id=current_user.id)
    if not category:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Category not found"
        )
    return category


@router.post("/",
    response_model=CategoryResponse,
    status_code=status.HTTP_201_CREATED
    )
def create_category(
    category_in: CategoryCreate,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Create new category
    """
    db_user = crud_user.get_by_keycloak_id(db, current_user["user_id"])
    if not db_user:
        # Автоматически создаем пользователя при первом входе
        db_user = crud_user.create_from_keycloak(
            db=db,
            keycloak_id=current_user["user_id"],
            username=current_user["username"],
            email=current_user["email"],
            full_name=current_user.get("name")
        )
    # Check if category with same name already exists
    existing = crud_category.get_by_name(
        db=db,
        name=category_in.name,
        user_id=db_user.id
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Category with name '{category_in.name}' already exists"
        )

    category = crud_category.create(db=db, obj_in=category_in, user_id=db_user.id)
    return category


@router.put("/{category_id}", response_model=CategoryResponse)
def update_category(
    category_id: int,
    category_in: CategoryUpdate,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Update category
    """
    category = crud_category.get(db=db, category_id=category_id, user_id=current_user.id)
    if not category:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Category not found"
        )

    # Check if new name conflicts with existing category
    if category_in.name and category_in.name != category.name:
        existing = crud_category.get_by_name(
            db=db,
            name=category_in.name,
            user_id=current_user["user_id"]
        )
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Category with name '{category_in.name}' already exists"
            )

    category = crud_category.update(db=db, db_obj=category, obj_in=category_in)
    return category


@router.delete("/{category_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_category(
    category_id: int,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Delete category
    """
    category = crud_category.delete(db=db, category_id=category_id, user_id=current_user.id)
    if not category:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Category not found"
        )
    return None
