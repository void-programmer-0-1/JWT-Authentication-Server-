from fastapi import (
    FastAPI,
    Depends,
    status
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from fastapi.security import OAuth2PasswordBearer
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession
from auth import (
    hash_password, verify_password, 
    create_access_token, decode_access_token
)
from models import (
    RegisterRequest, LoginRequest,LoginResponse, UpdateUserRequest,
    ReadUserRequest, DeleteUserRequest,
    generate_exception_message
)
from database import (
    init_db, close_engine, get_db,
    UserSchemaUtils, DBFlags
)


@asynccontextmanager
async def lifespan(server: FastAPI):
    try:
        await init_db()
        yield
    except Exception as err:
        print(err)
        print("Error occured in lifespan")
        await close_engine()
    finally:
        await close_engine()


server = FastAPI(lifespan=lifespan)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

user_db_util = UserSchemaUtils()


@server.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc: RequestValidationError):
    error_details = [
        {"message": err["msg"]}
        for err in exc.errors()
    ]
    print(error_details)
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"status": "error", "errors": error_details},
    )


@server.post("/register_api_route")
async def register(request: RegisterRequest, db: AsyncSession = Depends(get_db)):
    try:
        hashed_password = hash_password(request.password)
        response, db_conn_status = await user_db_util.create_user(
            db=db,
            username=request.username,
            email=request.email,
            password=hashed_password
        )

        if db_conn_status == DBFlags.SUCCESS:
            return {"status_code": "200", "response": response}
        
        if db_conn_status == DBFlags.UNIQUE_CONSTRAIN_ERR:
            return {"status_code":"422", "response": response}
        
        if db_conn_status == DBFlags.FAILED:
            return {"status_code":"500", "response": response}

    # handling invalid user model
    except ValidationError as validation_error:
        error_response = generate_exception_message(validation_error.error_count, validation_error.errors())
        print(error_response)
        return {"status_code": "422", "detail":"error_response"}
    
    except Exception as err:
        print("USER REGISTER LOG::{}".format(str(err)))
        return {"status_code": "400", "detail":"User already exists"}


@server.post("/login_api_route")
async def login_api_route(request: LoginRequest, db: AsyncSession = Depends(get_db)):
    user, response, db_conn_status = await user_db_util.get_user_with_username(db,request.username)
    
    if user is not None and db_conn_status == DBFlags.SUCCESS:
        if not user or not verify_password(plain_password=request.password, hashed_password=user.password):
            return {"status_code": "400", "detail": "Invalid User Credentials"}
    
    if user is None and db_conn_status == DBFlags.FAILED:
        return {"status_code": "500", "detail": response}

    access_token = create_access_token(data={"user_id": user.id})
    login_response = LoginResponse(access_token=access_token, token_type="bearer")
    return {"status_code": "200", **login_response.model_dump()}


@server.get("/user/all")
async def get_all_user_data(db: AsyncSession = Depends(get_db), _: str = Depends(oauth2_scheme)):
    
    users, response, db_conn_status = await user_db_util.get_all_users(db)
    if users == [] and response == "No users found" and db_conn_status == DBFlags.SUCCESS:
        return {"status_code": "200", "users": users, "message": response}
    
    if users == [] and response == "Unexpected Internal Server Failure" and db_conn_status == DBFlags.FAILED:
        return {"status_code": "500", "user": users, "message": response}
    
    if response == "success" and db_conn_status == DBFlags.SUCCESS:
        return {"status_code": "200", "user": users, "message": "success"}


@server.get("/user/read")
async def read_user_by_id(
    request: ReadUserRequest,
    db: AsyncSession = Depends(get_db), 
    _ : str = Depends(oauth2_scheme)
):
    user, response, status = await user_db_util.get_user_with_id(db, request.id)    
    if status == DBFlags.SUCCESS:
        return {"status_code": "200", "message": response,
                "user" : {
                    "id": user.id, 
                    "username": user.username,
                    "email": user.email, 
                    "password": user.password
                }}
    else:
        return {"status_code": "500", "messsage": response, "user": {}}


@server.put("/user/update")
async def update_user_by_id(
    request: UpdateUserRequest,
    db: AsyncSession = Depends(get_db), 
    _ : str = Depends(oauth2_scheme)
):
    response, status = await user_db_util.update_user(db, request.id, request.username, request.email, request.password)    
    if status == DBFlags.SUCCESS:
        return {"status_code": "200", "message": response}
    else:
        return {"status_code": "500", "messsage": response}
    

@server.delete("/user/delete")
async def delete_user_by_id(
    request: DeleteUserRequest,
    db: AsyncSession = Depends(get_db), 
    _ : str = Depends(oauth2_scheme)
):
    response, status = await user_db_util.delete_user(db, request.id)    
    if status == DBFlags.SUCCESS:
        return {"status_code": "200", "message": response}
    else:
        return {"status_code": "500", "messsage": response}
    

