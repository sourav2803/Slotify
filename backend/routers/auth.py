from fastapi import APIRouter, Depends,Request
from database import Base,SessionLocal
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Annotated
from models import Users
from passlib.context import CryptContext



router = APIRouter(
    prefix="",
    tags=["auth"]
)


bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

class CreateUser(BaseModel):
    username:str
    email:str
    first_name:str
    last_name:str
    password:str
    role:str
    
class Token(BaseModel):
    access_token:str

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
db_dependency = Annotated[Session,Depends(get_db)]




### Endpoints ###


def authenticate_user(username:str , password:str, db):
    user = db.query(Users).filter(Users.username == username ).first()
    if not user : 
        return False
    if not bcrypt_context.verify(password,user.hashed_password):
        return False
    return user

