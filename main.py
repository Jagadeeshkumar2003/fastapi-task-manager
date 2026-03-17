from sqlalchemy import Column, Integer, String, ForeignKey, Boolean
from fastapi import FastAPI, Depends, HTTPException, status, Request
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel, Field
from typing import List, Optional
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates 


SQLALCHEMY_DATABASE_URL = "mysql+mysqlconnector://root:supersecretpw@127.0.0.1:3306/fastapitodo"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


SECRET_KEY = "e8a8b5c4d1f9a6e2c3a7b4d9e0f1a5c8d9e2c3a7b4d9e0f1a5c8"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class TodoBase(BaseModel):
    item: str

class TodoCreate(TodoBase):
    pass

class Todo(TodoBase):
    id: int
    owner_id: int
    class Config:
        from_attributes = True

class UserBase(BaseModel):
    username: str
class UserCreate(UserBase):
    password: str = Field(..., min_length=6, max_length=50)



class User(UserBase):
    id: int
    is_active: bool
    todos: List[Todo] = []
    class Config:
        from_attributes = True

class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    hashed_password = Column(String(100), nullable=False)
    is_active = Column(Boolean, default=True)
    todos = relationship("TodoDB", back_populates="owner")

class TodoDB(Base):
    __tablename__ = "todos"
    id = Column(Integer, primary_key=True, index=True)
    item = Column(String(255), nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("UserDB", back_populates="todos")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password[:72], hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password[:72])

def get_user(db: Session, username: str):
    return db.query(UserDB).filter(UserDB.username == username).first()

def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(db, username=username)
    if user is None:
        raise credentials_exception
    return user

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="static")

@app.get("/")
def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/signup", response_model=User)
def signup(user: UserCreate, db: Session = Depends(get_db)):
    db_user = get_user(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(user.password)
    db_user = UserDB(username=user.username, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/init-db")
def init_db():
    Base.metadata.create_all(bind=engine)
    return {"message": "Database tables created!"}


@app.post("/todos/", response_model=Todo)
def create_todo(
    todo: TodoCreate, 
    current_user: UserDB = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    db_todo = TodoDB(item=todo.item, owner_id=current_user.id)
    db.add(db_todo)
    db.commit()
    db.refresh(db_todo)
    return db_todo
@app.get("/todos/", response_model=List[Todo])
def read_todos(
    current_user: UserDB = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    todos = db.query(TodoDB).filter(TodoDB.owner_id == current_user.id).all()
    return todos


@app.get("/todos/{todo_id}", response_model=Todo)
def read_todo(
    todo_id: int, 
    current_user: UserDB = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    todo = db.query(TodoDB).filter(TodoDB.id == todo_id, TodoDB.owner_id == current_user.id).first()
    if not todo:
        raise HTTPException(status_code=404, detail="Todo not found")
    return todo

@app.put("/todos/{todo_id}", response_model=Todo)
def update_todo(
    todo_id: int, 
    updated_todo: TodoCreate, 
    current_user: UserDB = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    db_todo = db.query(TodoDB).filter(TodoDB.id == todo_id, TodoDB.owner_id == current_user.id).first()
    if not db_todo:
        raise HTTPException(status_code=404, detail="Todo not found")
    db_todo.item = updated_todo.item
    db.commit()
    db.refresh(db_todo)
    return db_todo

@app.delete("/todos/{todo_id}")
def delete_todo(
    todo_id: int, 
    current_user: UserDB = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    db_todo = db.query(TodoDB).filter(TodoDB.id == todo_id, TodoDB.owner_id == current_user.id).first()
    if not db_todo:
        raise HTTPException(status_code=404, detail="Todo not found")
    db.delete(db_todo)
    db.commit()
    return {"message": "Todo deleted successfully"}