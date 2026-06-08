from fastapi import APIRouter, Depends, Request, HTTPException, status
from database import Base,SessionLocal
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Annotated
from models import Users
from passlib.context import CryptContext
from datetime import timedelta,datetime,timezone
from jose import jwt , JWTError
from fastapi.security import OAuth2PasswordBearer , OAuth2AuthorizationCodeBearer


router = APIRouter(
    prefix="",
    tags=["auth"]
)

SECRET_KEY = '197b2c37c391bed93fe80344fe73b806947a65e36206e05a1a23c2fa12702fe3'
ALGORITHM = 'HS256'

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')

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

def create_access_token(username:str , user_id:int , expires_delta:timedelta):
    encode = {'sub':username , 'id':user_id }
    expires = datetime.now(timezone.utc)+expires_delta
    encode.update({'exp':expires})
    return jwt.encode(encode,SECRET_KEY,algorithm=ALGORITHM)


async def get_current_user(token:Annotated[str,Depends(oauth2_bearer)]):
    try:
        payload = jwt.decode(token,SECRET_KEY,algorithms=ALGORITHM)
        username:str = payload.get('sub')
        user_id:int = payload.get('id')
        if username is None or user_id is None :
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail = 'Could not validate user.')
        return {'username': username , 'id': user_id }
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Could not validate user')
    

async def create_user(db:db_dependency,create_user_request:CreateUser):
    create_user_model = Users(
        email = create_user_request.email ,
        username = create_user_request.username ,
        firstname = create_user_request.firstname , 
        lastname = create_user_request.lastname , 
        hashed_password = bcrypt_context.hash(create_user_request.password),
        is_active=True 
    ) 
    db.add(create_user_model)
    db.commit()