from pydantic import BaseModel, field_validator


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str

    @field_validator("username")
    def validate_username(cls, username: str) -> str:
        if username == "" or len(username) <= 0:
            raise ValueError("username cannot be empty")
        if len(username) < 6:
            raise ValueError("username should contain atleast 6 character")

        return username

    @field_validator("email")
    def validate_email(cls, email: str) -> str:
        if email == "" or len(email) == 0:
            raise ValueError("Email cannot be empty")
        if "@" not in email:
            raise ValueError("@ is not present in the provided email")
        
        email_split = email.split("@")
        if len(email_split) == 2:
            user, domain = email_split
            if(
                (user == "" or len(user) == 0) or
                (domain == "" or len(domain) == 0)
            ):
                raise ValueError("Provided email is not in valid format")
            domain_split = domain.split(".")
            if len(domain_split) != 2:
                raise ValueError("domain in email is invalid")
        else:
            raise ValueError("Provided email is not in valid format")

        return email
    

    @field_validator("password")
    def validate_password(cls, password: str) -> str:
        if password == "" or len(password) == 0:
            raise ValueError("Password cannot be empty")
        if len(password) < 8:
            raise ValueError("password must contain atleast 8 characters")

        alpha_char_count: int = 0
        numeric_char_count: int = 0
        spl_char_count: int = 0

        for char in password:
            if char.isnumeric():
                numeric_char_count += 1
            elif char.isalpha():
                alpha_char_count += 1
            else:
                spl_char_count += 1
        
        if numeric_char_count < 2:
            raise ValueError("password must contain atleast 2 numberic characters")

        if spl_char_count < 2:
            raise ValueError("password must contain atleast 2 special characters")

        if alpha_char_count < 4:
            raise ValueError("password must contain atleast 4 alphabetic characters")

        return password


class LoginRequest(BaseModel):
    username: str
    password: str 

    @field_validator("username")
    def validate_username(cls, username: str) -> str:
        if username == "" or len(username) <= 0:
            raise ValueError("username cannot be empty")
        if len(username) < 6:
            raise ValueError("username should contain atleast 6 character")

        return username

    @field_validator("password")
    def validate_password(cls, password: str) -> str:
        if password == "" or len(password) == 0:
            raise ValueError("Password cannot be empty")
        if len(password) < 8:
            raise ValueError("password must contain atleast 8 characters")

        alpha_char_count: int = 0
        numeric_char_count: int = 0
        spl_char_count: int = 0

        for char in password:
            if char.isnumeric():
                numeric_char_count += 1
            elif char.isalpha():
                alpha_char_count += 1
            else:
                spl_char_count += 1
        
        if numeric_char_count < 2:
            raise ValueError("password must contain atleast 2 numberic characters")

        if spl_char_count < 2:
            raise ValueError("password must contain atleast 2 special characters")

        if alpha_char_count < 4:
            raise ValueError("password must contain atleast 4 alphabetic characters")

        return password


class LoginResponse(BaseModel):
    access_token: str
    token_type: str


class ReadUserRequest(BaseModel):
    id: int

    @field_validator("id")
    def validate_id(cls, id: int) -> int:
        if id <= 0:
            raise ValueError("id should not be zero or negative number")
        return id


class UpdateUserRequest(RegisterRequest):
    id: int

    @field_validator("id")
    def validate_id(cls, id: int) -> int:
        if id <= 0:
            raise ValueError("id should not be zero or negative number")
        return id


class DeleteUserRequest(BaseModel):
    id: int

    @field_validator("id")
    def validate_id(cls, id: int) -> int:
        if id <= 0:
            raise ValueError("id should not be zero or negative number")
        return id


def generate_exception_message(error_count: int, error_list: list) -> str:
    error_string = ""
    for i in range(error_count):
        error_string += error_list[i]["msg"]
        error_string += "\n" if i + 1 != error_count else ""
    return error_string