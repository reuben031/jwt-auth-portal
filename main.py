from fastapi import FastAPI, HTTPException, Depends, status, Form
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from models import UserCreate, UserLogin
from utils import hash_password, verify_password
from database import fake_users_db, save_users
from auth import create_access_token, SECRET_KEY, ALGORITHM, get_current_user
from fastapi.openapi.utils import get_openapi
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

# 🔧 Custom Swagger schema with Authorize JWT button
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="JWT Auth API",
        version="1.0.0",
        description="Login with JWT and access protected routes",
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "OAuth2PasswordBearer": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }
    for path in openapi_schema["paths"]:
        for method in openapi_schema["paths"][path]:
            if method in ["get", "post", "put", "delete"]:
                openapi_schema["paths"][path][method]["security"] = [{"OAuth2PasswordBearer": []}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# ✅ Signup route
@app.post("/signup")
def signup(user: UserCreate):
    # Check for duplicate username
    if user.username in fake_users_db:
        raise HTTPException(status_code=400, detail="Username already exists")

    # Check for duplicate email
    for u in fake_users_db.values():
        if u.get("email") == user.email:
            raise HTTPException(status_code=400, detail="Email already registered")

    hashed_pw = hash_password(user.password)

    # Store user
    fake_users_db[user.username] = {
        "username": user.username,
        "email": user.email,
        "password": hashed_pw,
        "role": user.role
    }

    save_users()  # persist to users.json

    print("\nCurrent fake_users_db:")
    print(fake_users_db)

    return {"message": f"User {user.username} created successfully"}

# ✅ Login route (Form-based)
@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    # Treat 'username' as email in frontend
    user_record = None
    for user in fake_users_db.values():
        if user.get("email") == username:
            user_record = user
            break

    if not user_record:
        raise HTTPException(status_code=401, detail="User not found. Please sign up first.")

    if not verify_password(password, user_record["password"]):
        raise HTTPException(status_code=401, detail="Incorrect password.")

    token = create_access_token({
        "sub": user_record["username"],
        "role": user_record["role"]
    })

    return {
        "access_token": token,
        "token_type": "bearer"
    }

# ✅ Profile route (any logged-in user)
@app.get("/profile")
def profile(current_user: dict = Depends(get_current_user)):
    return {
        "message": "Welcome to your profile!",
        "username": current_user["username"],
        "role": current_user["role"]
    }

# ✅ Admin-only route
@app.get("/admin-only")
def admin_only(current_user: dict = Depends(get_current_user)):
    if current_user["role"] not in ["admin", "superadmin"]:
        raise HTTPException(status_code=403, detail="Admins or Superadmins only!")
    return {
        "message": f"Hello {current_user['role'].title()} {current_user['username']}! You have access."
    }

# ✅ Superadmin-only route
@app.get("/superadmin-only")
def superadmin_only(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "superadmin":
        raise HTTPException(status_code=403, detail="Superadmins only!")
    return {
        "message": f"Greetings Superadmin {current_user['username']}! Full access granted."
    }

# ✅ Serve the HTML UI
@app.get("/")
def serve_home():
    return FileResponse(os.path.join("static", "index.html"))
