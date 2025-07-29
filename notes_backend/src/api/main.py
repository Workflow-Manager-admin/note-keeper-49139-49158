from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
from datetime import datetime

app = FastAPI(
    title="Note Keeper Backend API",
    description="API for managing user notes. Supports authentication, note CRUD, and search.",
    version="0.1.0",
    openapi_tags=[
        {"name": "auth", "description": "User authentication"},
        {"name": "notes", "description": "Note CRUD and search"}
    ]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------------------------
# DATA MODELS
# -------------------------------------------------------------------------

class UserCreate(BaseModel):
    """Pydantic model for user sign-up"""
    email: EmailStr = Field(..., description="User's unique email address")
    password: str = Field(..., min_length=6, description="User's password (min 6 characters)")

class UserLogin(BaseModel):
    """Pydantic model for user login"""
    email: EmailStr = Field(..., description="User's email")
    password: str = Field(..., description="User's password")

class UserOut(BaseModel):
    """Pydantic model for outputting user info (eg, after signup or login)"""
    id: int = Field(..., description="Unique identifier of the user")
    email: EmailStr = Field(..., description="User's unique email address")
    created_at: Optional[datetime] = Field(None, description="Account creation timestamp")

class Token(BaseModel):
    """Pydantic model for authentication token"""
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(..., description="Type of token, typically 'bearer'")

class NoteBase(BaseModel):
    """Base Note properties (for creation & update)"""
    title: str = Field(..., max_length=256, description="Title of the note")
    content: str = Field(..., description="Body/content of the note")

class NoteCreate(NoteBase):
    """Note creation model"""
    pass

class NoteUpdate(BaseModel):
    """Note update request model"""
    title: Optional[str] = Field(None, max_length=256, description="Title of the note")
    content: Optional[str] = Field(None, description="Body/content of the note")

class NoteOut(NoteBase):
    """Full details of a Note (including metadata)"""
    id: int = Field(..., description="Note ID")
    owner_id: int = Field(..., description="ID of the user who owns this note")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")

# -------------------------------------------------------------------------
# AUTHENTICATION (stub)
# -------------------------------------------------------------------------
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

# Dummy dependency for current user (stub for future DB integration)
# PUBLIC_INTERFACE
def get_current_user(token: str = Depends(oauth2_scheme)) -> UserOut:
    """
    Dummy get_current_user dependency.
    In production, this should verify JWT tokens and fetch user from DB.

    Returns:
        UserOut: The current authenticated user.
    """
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication not implemented"
    )

# -------------------------------------------------------------------------
# ROUTES
# -------------------------------------------------------------------------

@app.get("/", tags=["health"])
def health_check():
    """Health check endpoint."""
    return {"message": "Healthy"}

# ------------- Auth Endpoints --------------------

# PUBLIC_INTERFACE
@app.post("/auth/signup", response_model=UserOut, summary="User sign-up", tags=["auth"])
def signup(user: UserCreate):
    """
    Create a new user account.
    """
    pass  # placeholder

# PUBLIC_INTERFACE
@app.post("/auth/token", response_model=Token, summary="User login (token)", tags=["auth"])
def login(user: UserLogin):
    """
    Authenticate user and return access token.
    """
    pass  # placeholder

# ------------- Notes CRUD Endpoints --------------------

# PUBLIC_INTERFACE
@app.get(
    "/notes",
    response_model=List[NoteOut],
    summary="List or search notes",
    tags=["notes"]
)
def list_notes(
    q: Optional[str] = None,
    skip: int = 0,
    limit: int = 20,
    current_user: UserOut = Depends(get_current_user)
):
    """
    List all notes owned by current user. 
    Optionally search by title/content with query 'q'.
    
    - **q**: Search string for filtering notes by title/content.
    - **skip**: Number of notes to skip.
    - **limit**: Maximum number of notes to return.
    """
    pass  # placeholder

# PUBLIC_INTERFACE
@app.post(
    "/notes",
    response_model=NoteOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new note",
    tags=["notes"]
)
def create_note(
    note: NoteCreate,
    current_user: UserOut = Depends(get_current_user)
):
    """
    Create a new note for the current user.
    """
    pass  # placeholder

# PUBLIC_INTERFACE
@app.get(
    "/notes/{note_id}",
    response_model=NoteOut,
    summary="Get a specific note",
    tags=["notes"]
)
def get_note(
    note_id: int,
    current_user: UserOut = Depends(get_current_user)
):
    """
    Retrieve a note by ID (must belong to current user).
    """
    pass  # placeholder

# PUBLIC_INTERFACE
@app.put(
    "/notes/{note_id}",
    response_model=NoteOut,
    summary="Update a note",
    tags=["notes"]
)
def update_note(
    note_id: int,
    note: NoteUpdate,
    current_user: UserOut = Depends(get_current_user)
):
    """
    Update an existing note (partial update is allowed).
    """
    pass  # placeholder

# PUBLIC_INTERFACE
@app.delete(
    "/notes/{note_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a note",
    tags=["notes"]
)
def delete_note(
    note_id: int,
    current_user: UserOut = Depends(get_current_user)
):
    """
    Delete a note by ID (must belong to current user).
    """
    pass  # placeholder

