from fastapi import Depends, FastAPI, HTTPException, Request
from tortoise.contrib.fastapi import register_tortoise
from models import *
from authentication import (get_hashed_password, verify_token)
from fastapi import status
import logging

# signals
from tortoise.signals import post_save
from typing import List, Optional, Type
from tortoise import BaseDBAsyncClient
from emails import (send_email)

# response classes
from fastapi.responses import HTMLResponse, JSONResponse

# Authentication
import jwt
from authentication import *
from fastapi.security import (OAuth2PasswordBearer, OAuth2PasswordRequestForm)

#templates
from fastapi.templating import Jinja2Templates

#image uplaod
from fastapi import File, UploadFile
import secrets
from fastapi.staticfiles import StaticFiles
from PIL import Image

description = """
    EcommerceAPI is here to rock the world !  🚀 🚀 🚀
"""

metadata_tags = [
    {
        "name": "Auth", 
    }, 
    {
        "name": "User", 
    }, 
    {
        "name": "Product"
    }
]

app = FastAPI(
    title="EcommerceAPI",
    description=description, 
    version="0.0.1", 
    contact={
        "name": "Abbas", 
        "email": "abbas.devcode@gmail.com", 
    },
    # docs_url="/api/v1/docs" , 
    # redoc_url="/api/v1/redoc", 
    # openapi_url="/api/v1/openapi.json", 
    openapi_tags=metadata_tags
)

# ENDPOINT = "http://localhost:8000/"
# API_BASE_PATH = "api/v1"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl= 'token')

#static file setup config
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.post('/token', include_in_schema=False, tags=["Auth"])
async def generate_token(request_form: OAuth2PasswordRequestForm = Depends()):

    token = await token_generator(request_form.username, request_form.password)

    return {
        'access_token' : token, 
        'token_type': 'bearer'
    }

async def get_current_user(token: str = Depends(oauth2_scheme), tags=["Auth"]):
    try:
        payload = jwt.decode(token, config_credentials['SECRET'], algorithms = ['HS256'])
        user = await User.get(id = payload.get("id"))
    except:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED, 
            detail = "Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
        print("Ch4")

    return await user


@app.post('/user/me', tags=["User"])
async def user_login(user: user_pydantic = Depends(get_current_user)):
    business = await Business.get(owner = user)
    logo = business.logo
    logo_path = "localhost:8000/static/images/" + logo
    
    return {
        "status": "ok", 
        "data": {
            "username": user.username, 
            "email": user.email, 
            "verified": user.is_verified, 
            "logo": logo_path
        }
    }

@app.get("/users/all", tags=["User"])
async def get_all_users():
    users = await User.all()
    list = []
    
    for user in users:
        userpy = await user_pydantic.from_tortoise_orm(user)
        list.append(userpy.dict())

    return list

@post_save(User)
async def create_business(
    sender: "Type[User]", 
    instance: User, 
    created: bool, 
    using_db: "Optional[BaseDBAsyncClient]", 
    update_fields: List[str]) -> None:
    if created:
        business_obj = await Business.create(
            business_name = instance.username, owner = instance
        )

        await business_pydantic.from_tortoise_orm(business_obj)

        # send the email
        await send_email([instance.email], instance)

@app.post("/register", tags=["Auth"])
async def user_registration(user: user_pydanticIn):
    user_info = user.dict(exclude_unset=True)
    user_info["password"] = get_hashed_password(user_info["password"])
    user_obj = await User.create(**user_info)
    new_user = await user_pydantic.from_tortoise_orm(user_obj)

    return {
        "status": "ok", 
        "data": new_user.dict(),
        "message": f"Hello {new_user.username}, thanks for signing up!"
    }

@app.post("/product", tags=["Product"])
async def add_new_product(product: product_pydanticIn, user: user_pydantic = Depends(get_current_user)):
    product = product.dict(exclude_unset=True)

    # to avoid division by zero error
    if product["original_price"] > 0:
        product["percentage_discount"] = ((product["original_price"] - product['new_price']) / product["original_price"]) * 100

    else: 
        return {
            "status": "error"
        }

    product_obj = await Product.create(**product, business = user)
    product_obj = await product_pydantic.from_tortoise_orm(product_obj)

    return {
        "status": "ok", 
        "detail": "Product created successfully", 
        "data": product_obj
    }

@app.get("/product", tags=["Product"])
async def get_all_products():
    products = Product.all()
    products = await product_pydantic.from_queryset(products)
    return {
        "status": "ok", 
        "detail": "Products returned successfully", 
        "data": products, 
    }


@app.get("/product/{id}", tags=["Product"])
async def get_product_details(id: int):
    product = await Product.get(id = id)
    business = await product.business
    owner = await business.owner
    business = await business_pydantic.from_tortoise_orm(business)
    owner_obj = await user_pydantic.from_tortoise_orm(owner)
    response = await product_pydantic.from_tortoise_orm(product)

    return {
        "status": "ok", 
        "detail": "data returned successfully", 
        "data": {
            "product_details": response, 
            "owner": owner_obj, 
            "business": business
        }
    }

@app.delete("/product/{id}", tags=["Product"]) 
async def delete_product(id: int, user: user_pydantic = Depends(get_current_user)):
    product = await Product.get(id = id)
    business = await product.business
    owner = await business.owner

    if user == owner:
        product.delete()
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail = "Not authenticated to perform this action", 
            headers = {"WWW-Authenticate": "Bearer"}
        )

    return {
        "status": "ok"
    }

@app.put("/product/{id}", tags=["Product"])
async def update_product(id: int, update_info: product_pydanticIn, user: user_pydantic = Depends(get_current_user)):
    product = await Product.get(id = id)
    business = await product.business
    owner = await business.owner

    update_info = update_info.dict(exclude_unset=True)
    update_info["date_published"] = datetime.utcnow

    if user == owner and update_info["original_price"] > 0:
        update_info["percentage_discount"] = ((update_info["original_price"] - update_info["new_price"]) / update_info["original_price"] ) * 100
        product = await product.update_from_dict(update_info)

        product.save()

        response = await product_pydantic.from_tortoise_orm(product)

        return {
            "status": "ok", 
            "data": response, 
            "detail": "Product updated successfully"
        }

    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated to upload image", 
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.get("/", tags=["Misc"], include_in_schema=False)
@app.get("/status", tags=["Misc"], include_in_schema=False)
def status():
    return {
        "status": "Ok"
        }


templates = Jinja2Templates(directory="templates")

@app.get("/verification", response_class=HTMLResponse, tags=["Auth"])
async def email_verification(request: Request, token: str):
    user = await verify_token(token)

    if user and not user.is_verified:
        user.is_verified = True
        await user.save()
        return templates.TemplateResponse("verification.html", {"request": request, "username": user.username})

    raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED, 
            detail = "Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.post("/uploadfile/profile", tags=["User"])
async def create_upload_file(file: UploadFile = File(...), user: user_pydantic = Depends(get_current_user)):
    FILEPATH = "./static/images"
    filename = file.filename
    extension = filename.split(".")[1]

    if extension not in ["png", "jpg", "jpeg", "svg"]:
        return {
            "status": "error", 
            "detail": "Image format unsupported"
        }

    token_name = secrets.token_hex(10) + "." + extension
    generated_name = FILEPATH + token_name

    file_content = await file.read()

    with open(generated_name, "wb") as file:
        file.write(file_content)

    #pillow
    img = Image.open(generated_name)
    img = img.resize(size = (200, 200))
    img.save(generated_name)

    file.close()

    business = await Business.get(owner = user)
    owner = await business.owner

    if owner == user :
        business.logo = token_name
        await business.save()
        
        fileurl = 'localhost:8000' + generated_name[1:]
        return {
            'status': 'ok', 
            'detail': 'successfully uploaded the image', 
            'filename': fileurl, 
            
        }

    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Not authenticated to upload image", 
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.post('/uploadfile/product/{id}', tags=["Product"])
async def upload_product_image(id: int, file: UploadFile = File(...), user: user_pydantic = Depends(get_current_user)):
    FILEPATH = "./static/images"
    filename = file.filename
    extension = filename.split(".")[1]

    if extension not in ["png", "jpg", "jpeg", "svg"]:
        return {
            "status": "error", 
            "detail": "Image format unsupported"
        }

    token_name = secrets.token_hex(10) + "." + extension
    generated_name = FILEPATH + token_name

    file_content = await file.read()

    with open(generated_name, "wb") as file:
        file.write(file_content)

    #pillow
    img = Image.open(generated_name)
    img = img.resize(size = (200, 200))
    img.save(generated_name)

    file.close()

    product = await Product.get(id = id)
    business = await product.business
    owner = await business.owner

    if owner == user:
        product.product_image = token_name
        await product.save()

        fileurl = 'localhost:8000' + generated_name[1:]
        return {
            'status': 'ok', 
            'detail': 'successfully uploaded the image', 
            'filename': fileurl,    
        }

    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Not authenticated to upload image", 
            headers={"WWW-Authenticate": "Bearer"},
        )


register_tortoise(
    app, 
    db_url="sqlite://database.sqlite3", 
    modules = {
        "models": ["models"]}, 
    generate_schemas=True, 
    add_exception_handlers=True
)
