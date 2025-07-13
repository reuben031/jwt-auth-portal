from pydantic import BaseModel, EmailStr, validator
import re

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str  # user, admin, superadmin

    @validator('username')
    def validate_username(cls, v):
        if len(v.strip()) < 3:
            raise ValueError("Username must be at least 3 characters long")
        return v

    @validator('password')
    def validate_password(cls, v):
        # At least one lowercase, one uppercase, one number, one symbol, min 8 chars
        pattern = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$')
        if not pattern.match(v):
            raise ValueError("Password must include uppercase, lowercase, number, symbol, and be 8+ characters")
        return v

    @validator('role')
    def validate_role(cls, v):
        allowed_roles = ["user", "admin", "superadmin"]
        if v not in allowed_roles:
            raise ValueError(f"Role must be one of: {', '.join(allowed_roles)}")
        return v

class UserLogin(BaseModel):
    username: str
    password: str
