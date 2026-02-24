# --- Centers, Groups, Instructors Models & Admin Dashboard ---

# Pydantic models
class Center(BaseModel):
    name: str
    address: str

class Group(BaseModel):
    name: str
    activity: str
    instructor: str
    schedule: str

class Instructor(BaseModel):
    name: str
    email: str

# Centers CRUD
@app.post("/centers", dependencies=[Depends(require_role(ROLE_ADMIN))])
async def create_center(center: Center):
    await db["centers"].insert_one(center.dict())
    return {"message": "Center created"}

@app.get("/centers")
async def list_centers():
    centers = [c async for c in db["centers"].find()]
    for c in centers:
        c["id"] = str(c["_id"])
        c.pop("_id", None)
    return centers

# Groups CRUD
@app.post("/groups", dependencies=[Depends(require_role(ROLE_ADMIN))])
async def create_group(group: Group):
    await db["groups"].insert_one(group.dict())
    return {"message": "Group created"}

@app.get("/groups")
async def list_groups():
    groups = [g async for g in db["groups"].find()]
    for g in groups:
        g["id"] = str(g["_id"])
        g.pop("_id", None)
    return groups

# Instructors CRUD
@app.post("/instructors", dependencies=[Depends(require_role(ROLE_ADMIN))])
async def create_instructor(instructor: Instructor):
    await db["instructors"].insert_one(instructor.dict())
    return {"message": "Instructor created"}

@app.get("/instructors")
async def list_instructors():
    instructors = [i async for i in db["instructors"].find()]
    for i in instructors:
        i["id"] = str(i["_id"])
        i.pop("_id", None)
    return instructors

# --- Admin Dashboard Endpoints ---
from fastapi import Query

@app.get("/admin/dashboard", dependencies=[Depends(require_role(ROLE_ADMIN))])
async def admin_dashboard():
    activity_count = await db["activities"].count_documents({})
    user_count = await db["users"].count_documents({})
    group_count = await db["groups"].count_documents({})
    center_count = await db["centers"].count_documents({})
    instructor_count = await db["instructors"].count_documents({})
    return {
        "activities": activity_count,
        "users": user_count,
        "groups": group_count,
        "centers": center_count,
        "instructors": instructor_count
    }

@app.get("/admin/enrollment-analytics", dependencies=[Depends(require_role(ROLE_ADMIN))])
async def enrollment_analytics():
    # Example: return activity names and participant counts
    activities = [a async for a in db["activities"].find()]
    analytics = [
        {"name": a["name"], "participants": len(a.get("participants", []))}
        for a in activities
    ]
    return analytics
# --- User Registration, Login, and RBAC ---

from typing import Optional
from fastapi import Body

# Registration endpoint
class UserCreate(BaseModel):
    email: str
    password: str
    full_name: Optional[str] = None
    role: str = ROLE_STUDENT

@app.post("/register")
async def register(user: UserCreate):
    existing = await db["users"].find_one({"email": user.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_pw = get_password_hash(user.password)
    user_doc = {
        "email": user.email,
        "full_name": user.full_name,
        "hashed_password": hashed_pw,
        "role": user.role,
        "disabled": False
    }
    await db["users"].insert_one(user_doc)
    return {"message": "User registered successfully"}

# Login endpoint (JWT token)
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await db["users"].find_one({"email": form_data.username})
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token = create_access_token({"sub": user["email"], "role": user["role"]})
    return {"access_token": access_token, "token_type": "bearer"}

# Get current user info (protected)
@app.get("/users/me")
async def read_users_me(current_user: UserInDB = Depends(get_current_user)):
    user = current_user.dict()
    user.pop("hashed_password", None)
    return user

# Role-based dependency
def require_role(role: str):
    async def role_checker(current_user: UserInDB = Depends(get_current_user)):
        if current_user.role != role:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return current_user
    return role_checker
"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
import motor.motor_asyncio
import os
from pathlib import Path
from dotenv import load_dotenv


# Load environment variables
load_dotenv()

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

# MongoDB setup
MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "mergington")
client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]

# JWT and password hashing setup
SECRET_KEY = os.getenv("JWT_SECRET", "supersecretkey")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# User roles
ROLE_ADMIN = "admin"
ROLE_OPERATOR = "operator"
ROLE_STUDENT = "student"

# User model


class User(BaseModel):
    email: str
    full_name: str | None = None
    disabled: bool = False
    role: str = ROLE_STUDENT


class UserInDB(User):
    hashed_password: str

# Utility functions for password hashing and JWT


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict):
    to_encode = data.copy()
    import datetime
    expire = datetime.datetime.utcnow(
    ) + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Dependency to get current user from JWT


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = await db["users"].find_one({"email": email})
    if user is None:
        raise credentials_exception
    return UserInDB(**user)

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")


# MongoDB activities collection will be used instead of in-memory


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")



from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

@app.get("/activities")
async def get_activities():
    activities_cursor = db["activities"].find()
    activities = []
    async for activity in activities_cursor:
        activity["id"] = str(activity["_id"])
        activity.pop("_id", None)
        activities.append(activity)
    return JSONResponse(content=activities)




# --- Waitlist and Auth-protected Signup ---
from fastapi import Security

@app.post("/activities/{activity_name}/signup")
async def signup_for_activity(activity_name: str, current_user: UserInDB = Depends(get_current_user)):
    """Sign up a student for an activity (MongoDB, waitlist support, auth required)"""
    email = current_user.email
    activity = await db["activities"].find_one({"name": activity_name})
    if not activity:
        raise HTTPException(status_code=404, detail="Activity not found")
    if email in activity.get("participants", []):
        raise HTTPException(status_code=400, detail="Student is already signed up")
    if email in activity.get("waitlist", []):
        raise HTTPException(status_code=400, detail="Student is already on the waitlist")
    if len(activity.get("participants", [])) >= activity.get("max_participants", 0):
        # Add to waitlist
        await db["activities"].update_one(
            {"name": activity_name},
            {"$push": {"waitlist": email}}
        )
        return {"message": f"Activity is full. {email} added to waitlist for {activity_name}"}
    await db["activities"].update_one(
        {"name": activity_name},
        {"$push": {"participants": email}}
    )
    return {"message": f"Signed up {email} for {activity_name}"}




@app.delete("/activities/{activity_name}/unregister")
async def unregister_from_activity(activity_name: str, current_user: UserInDB = Depends(get_current_user)):
    """Unregister a student from an activity (MongoDB, waitlist support, auth required)"""
    email = current_user.email
    activity = await db["activities"].find_one({"name": activity_name})
    if not activity:
        raise HTTPException(status_code=404, detail="Activity not found")
    if email not in activity.get("participants", []):
        raise HTTPException(status_code=400, detail="Student is not signed up for this activity")
    # Remove student
    await db["activities"].update_one(
        {"name": activity_name},
        {"$pull": {"participants": email}}
    )
    # Promote from waitlist if any
    updated = await db["activities"].find_one({"name": activity_name})
    waitlist = updated.get("waitlist", [])
    if waitlist:
        next_email = waitlist[0]
        await db["activities"].update_one(
            {"name": activity_name},
            {"$push": {"participants": next_email}, "$pull": {"waitlist": next_email}}
        )
    return {"message": f"Unregistered {email} from {activity_name}"}
# --- Assignment Endpoints ---

# Assign a student to a group
@app.post("/groups/{group_name}/assign-student", dependencies=[Depends(require_role(ROLE_ADMIN))])
async def assign_student_to_group(group_name: str, student_email: str = Body(...)):
    group = await db["groups"].find_one({"name": group_name})
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    await db["groups"].update_one(
        {"name": group_name},
        {"$addToSet": {"students": student_email}}
    )
    return {"message": f"Assigned {student_email} to group {group_name}"}

# Assign an instructor to an activity
@app.post("/activities/{activity_name}/assign-instructor", dependencies=[Depends(require_role(ROLE_ADMIN))])
async def assign_instructor_to_activity(activity_name: str, instructor_email: str = Body(...)):
    activity = await db["activities"].find_one({"name": activity_name})
    if not activity:
        raise HTTPException(status_code=404, detail="Activity not found")
    await db["activities"].update_one(
        {"name": activity_name},
        {"$set": {"instructor": instructor_email}}
    )
    return {"message": f"Assigned instructor {instructor_email} to activity {activity_name}"}
