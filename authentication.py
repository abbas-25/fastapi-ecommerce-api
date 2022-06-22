from passlib.context import CryptContext 
import jwt
from dotenv import dotenv_values
from models import User
from fastapi import status, HTTPException

config_credentials = dotenv_values(".env")

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

def get_hashed_password(password):
    return pwd_context.hash(password)

async def verify_token(token: str):
    try:
        payload = jwt.decode(token, config_credentials['SECRET'], algorithms = ['HS256'])
        user = await User.get(id = payload.get('id'))
    except:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED, 
            detail = "Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user

def verify_password(input, actual):
    return pwd_context.verify(input, actual)

async def authenticate_user(user, passw):
    user = await User.get(username = user)
    if user and verify_password(passw, user.password):
        return user
    return False


async def token_generator(username, password):
    try:
        user = await authenticate_user(username, password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Invalid username or password", 
                headers={"WWW-Authenticate": "Bearer"}
            )
        token_data = {
            "id": user.id, 
            "username": user.username
        }

        token = jwt.encode(token_data, config_credentials['SECRET'], algorithm='HS256')

        return token
    except:
        raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, 
                detail="Something went wrong!", 
                headers={"WWW-Authenticate": "Bearer"}
            )