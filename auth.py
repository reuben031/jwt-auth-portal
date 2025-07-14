from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from database import fake_users_db  # fake DB dictionary
import logging

# Setup logger
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# 🔐 Secret config
SECRET_KEY = "your_secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# 🔧 Token generator
def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# 📦 OAuth2 token scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# ✅ Decode token manually (optional helper)
def decode_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError as e:
        logger.warning(f"Token decoding failed: {e}")
        return None

# 👤 Get current user from JWT token
def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None or role is None:
            logger.warning("Token missing username or role")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
            )
        return {"username": username, "role": role}
    except JWTError as e:
        logger.warning(f"Token verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token or expired",
        )

# 🔐 Require superadmin-only access
def require_superadmin(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user["role"] != "superadmin":
        logger.warning(f"Access denied: {current_user['username']} is not superadmin")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superadmins only!"
        )
    return current_user
