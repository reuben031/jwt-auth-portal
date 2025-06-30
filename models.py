from pydantic import BaseModel, validator

class UserCreate(BaseModel):
    username: str
    password: str
    role: str  # should be "user", "admin", or "superadmin"

    @validator('role')
    def validate_role(cls, v):
        allowed_roles = ["user", "admin", "superadmin"]
        if v not in allowed_roles:
            raise ValueError(f"Role must be one of: {', '.join(allowed_roles)}")
        return v

class UserLogin(BaseModel):
    username: str
    password: str
