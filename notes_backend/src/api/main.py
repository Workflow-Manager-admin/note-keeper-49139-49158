from fastapi import FastAPI, Depends, HTTPException, status, Query, Path
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from typing import List, Optional
from datetime import datetime, timedelta
from pydantic import BaseModel, Field, EmailStr
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlmodel import Field as ORMField, SQLModel, create_engine, Session, select
import os

# ==================== CONFIG ====================
SECRET_KEY = os.environ.get('SECRET_KEY', 'notsosecret')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 1 day

DB_PATH = os.environ.get("DB_PATH", "sqlite:///notes.db")

app = FastAPI(
    title="Note Keeper Backend API",
    description=(
        "API for managing user notes. Supports authentication, note CRUD, and search.\n\n"
        "**Usage notes:**\n"
        "- Authenticate first using `/auth/signup` and `/auth/token` endpoints to receive your access token.\n"
        "- For note endpoints, you must include the `Authorization: Bearer <token>` header in your requests.\n"
        "- CORS allows requests only from the configured React frontend (set via FRONTEND_ORIGIN env variable).\n"
        "- See each endpoint for summary and details. All endpoint responses are JSON."
    ),
    version="0.1.0",
    openapi_tags=[
        {"name": "auth", "description": "User authentication"},
        {"name": "notes", "description": "Note CRUD and search"}
    ],
)

# Set allowed origins for CORS to restrict to the frontend React domain
# You can customize later if deployed, e.g. ["https://notes.yoursite.com"]
FRONTEND_ORIGIN = os.environ.get("FRONTEND_ORIGIN", "http://localhost:3000")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== SQLModel ORM MODELS ====================
class Note(SQLModel, table=True):
    id: Optional[int] = ORMField(default=None, primary_key=True)
    title: str = ORMField(max_length=256, index=True)
    content: str
    owner_id: int = ORMField(foreign_key="user.id", index=True)
    created_at: datetime = ORMField(default_factory=datetime.utcnow)
    updated_at: datetime = ORMField(default_factory=datetime.utcnow)

class User(SQLModel, table=True):
    id: Optional[int] = ORMField(default=None, primary_key=True)
    email: str = ORMField(index=True, unique=True, nullable=False)
    hashed_password: str
    created_at: datetime = ORMField(default_factory=datetime.utcnow)

# ==================== Pydantic SCHEMAS ====================
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

# ==================== DB INIT ====================
engine = create_engine(DB_PATH, echo=False)
SQLModel.metadata.create_all(engine)

# ==================== PASSWORD & TOKEN ====================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ==================== USER HELPERS ====================
def get_user_by_email(db: Session, email: str) -> Optional[User]:
    statement = select(User).where(User.email == email)
    return db.exec(statement).first()

def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
    return db.get(User, user_id)

def authenticate_user(db: Session, email: str, password: str) -> Optional[User]:
    user = get_user_by_email(db, email)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

# ==================== DEPENDENCIES ====================
def get_db():
    with Session(engine) as session:
        yield session

# PUBLIC_INTERFACE
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> UserOut:
    """
    Extract and verify JWT token, then return user.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: Optional[int] = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user_by_id(db, user_id)
    if not user:
        raise credentials_exception
    return UserOut(id=user.id, email=user.email, created_at=user.created_at)

# ==================== ROUTES ====================

@app.get("/", tags=["health"])
def health_check():
    """Health check endpoint."""
    return {"message": "Healthy"}

# ------------- Auth Endpoints --------------------

# PUBLIC_INTERFACE
@app.post("/auth/signup", response_model=UserOut, summary="User sign-up", tags=["auth"])
def signup(user: UserCreate, db: Session = Depends(get_db)):
    """
    Create a new user account.
    """
    db_user = get_user_by_email(db, user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_pw = get_password_hash(user.password)
    new_user = User(email=user.email, hashed_password=hashed_pw)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return UserOut(id=new_user.id, email=new_user.email, created_at=new_user.created_at)

# PUBLIC_INTERFACE
@app.post("/auth/token", response_model=Token, summary="User login (token)", tags=["auth"])
def login(user: UserLogin, db: Session = Depends(get_db)):
    """
    Authenticate user and return access token.
    """
    db_user = authenticate_user(db, user.email, user.password)
    if not db_user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": db_user.id})
    return Token(access_token=access_token, token_type="bearer")

# ------------- Notes CRUD Endpoints --------------------

# PUBLIC_INTERFACE
@app.get(
    "/notes",
    response_model=List[NoteOut],
    summary="List or search notes",
    tags=["notes"]
)
def list_notes(
    q: Optional[str] = Query(None, description="Search string for filtering notes by title/content."),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    current_user: UserOut = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List all notes owned by current user. 
    Optionally search by title/content with query 'q'.
    - **q**: Search string for filtering notes by title/content.
    - **skip**: Number of notes to skip.
    - **limit**: Maximum number of notes to return.
    """
    query = select(Note).where(Note.owner_id == current_user.id)
    if q:
        like_str = f"%{q}%"
        query = query.where((Note.title.ilike(like_str)) | (Note.content.ilike(like_str)))
    query = query.offset(skip).limit(limit)
    results = db.exec(query).all()
    return [
        NoteOut(
            id=n.id,
            title=n.title,
            content=n.content,
            owner_id=n.owner_id,
            created_at=n.created_at,
            updated_at=n.updated_at,
        )
        for n in results
    ]

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
    current_user: UserOut = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create a new note for the current user.
    """
    now = datetime.utcnow()
    db_note = Note(
        title=note.title,
        content=note.content,
        owner_id=current_user.id,
        created_at=now,
        updated_at=now
    )
    db.add(db_note)
    db.commit()
    db.refresh(db_note)
    return NoteOut(
        id=db_note.id,
        title=db_note.title,
        content=db_note.content,
        owner_id=db_note.owner_id,
        created_at=db_note.created_at,
        updated_at=db_note.updated_at,
    )

# PUBLIC_INTERFACE
@app.get(
    "/notes/{note_id}",
    response_model=NoteOut,
    summary="Get a specific note",
    tags=["notes"]
)
def get_note(
    note_id: int = Path(..., ge=1, description="Note ID"),
    current_user: UserOut = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retrieve a note by ID (must belong to current user).
    """
    note = db.get(Note, note_id)
    if note is None or note.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Note not found")
    return NoteOut(
        id=note.id,
        title=note.title,
        content=note.content,
        owner_id=note.owner_id,
        created_at=note.created_at,
        updated_at=note.updated_at,
    )

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
    current_user: UserOut = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update an existing note (partial update is allowed).
    """
    db_note = db.get(Note, note_id)
    if db_note is None or db_note.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Note not found")
    update_data = note.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_note, key, value)
    db_note.updated_at = datetime.utcnow()
    db.add(db_note)
    db.commit()
    db.refresh(db_note)
    return NoteOut(
        id=db_note.id,
        title=db_note.title,
        content=db_note.content,
        owner_id=db_note.owner_id,
        created_at=db_note.created_at,
        updated_at=db_note.updated_at,
    )

# PUBLIC_INTERFACE
@app.delete(
    "/notes/{note_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a note",
    tags=["notes"]
)
def delete_note(
    note_id: int,
    current_user: UserOut = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Delete a note by ID (must belong to current user).
    """
    db_note = db.get(Note, note_id)
    if db_note is None or db_note.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Note not found")
    db.delete(db_note)
    db.commit()
    return

