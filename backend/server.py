from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr, validator, Field
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone, timedelta
import os
import logging
import jwt
import uuid
import ipaddress
import re
from dotenv import load_dotenv
from pathlib import Path
# Use httpx directly for Cloudflare API calls
from enum import Enum
import httpx

# Load environment variables
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# MongoDB connection
mongo_url = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ.get('DB_NAME', 'subdomain_reseller')]

# Cloudflare settings from the provided configuration
CLOUDFLARE_SETTINGS = {
    "1": {
        "zone": "6a744d80e47fd7360c493ac52c228bc9",
        "apitoken": "7VkDw7pGMuONgGyXo_66VOdVwelgLc7Fj-cpzsRQ",
        "tld": "hosting-privateku.web.id"
    },
    "2": {
        "zone": "366a62f44de19a2c8ed81adbe4485929", 
        "apitoken": "NmO7m7UiErFtzcHZQ9ZhGwO0ZvuB4VuT1EX8Bn_n",
        "tld": "hosting-panelku.biz.id"
    },
    "3": {
        "zone": "78a4a2506b6bbaf1d20cb0b212c43bdf",
        "apitoken": "7VkDw7pGMuONgGyXo_66VOdVwelgLc7Fj-cpzsRQ", 
        "tld": "hostingku-private.web.id"
    },
    "4": {
        "zone": "45aee2c21409fa3488a4d8682b52aefb",
        "apitoken": "7VkDw7pGMuONgGyXo_66VOdVwelgLc7Fj-cpzsRQ",
        "tld": "hosting-private.web.id"
    },
    "5": {
        "zone": "fa4794151634d2ef9b9b76f375778ae3",
        "apitoken": "7VkDw7pGMuONgGyXo_66VOdVwelgLc7Fj-cpzsRQ",
        "tld": "mafiahytam.my.id"
    },
    "6": {
        "zone": "f521c2a8f7910d5594d2dab417e32a94",
        "apitoken": "7VkDw7pGMuONgGyXo_66VOdVwelgLc7Fj-cpzsRQ",
        "tld": "private-hosting.web.id"
    },
    "7": {
        "zone": "087e164c1fdcc889e0310d3008105e6d",
        "apitoken": "7VkDw7pGMuONgGyXo_66VOdVwelgLc7Fj-cpzsRQ",
        "tld": "serverpribgw.biz.id"
    }
}

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-here')
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = 24

# FastAPI app setup
app = FastAPI(title="Website Subdomain Reseller", version="1.0.0")
api_router = APIRouter(prefix="/api")

# Security
security = HTTPBearer()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class UserRole(str, Enum):
    USER = "user"
    RESELLER = "reseller"
    ADMIN = "admin"

class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: EmailStr
    password: str
    nama: str
    role: UserRole
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    nama: str
    role: UserRole

class UserLogin(BaseModel):
    email: EmailStr
    password: str
    role: UserRole

class SubdomainCreate(BaseModel):
    hostname: str
    ip_address: str
    tld_id: str

    @validator('hostname')
    def validate_hostname(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError("Hostname cannot be empty")
        
        # Remove any existing domain suffix and validate format
        hostname = v.lower().strip()
        if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$', hostname):
            raise ValueError("Invalid hostname format")
        
        return hostname

    @validator('ip_address')
    def validate_ip(cls, v):
        try:
            ipaddress.IPv4Address(v)
        except ipaddress.AddressValueError:
            raise ValueError("Invalid IPv4 address")
        return v

class Subdomain(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_email: str
    hostname: str
    ip_address: str
    tld: str
    subdomain: str  # full subdomain like "test.hosting-privateku.web.id"
    node_subdomain: str  # node subdomain like "node.test.hosting-privateku.web.id"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# Authentication functions
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRE_HOURS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid authentication")
        return payload
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication")

async def get_current_user(payload: dict = Depends(verify_token)):
    user = await db.users.find_one({"email": payload.get("sub")})
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return User(**user)

# Cloudflare DNS service
class CloudflareService:
    @staticmethod
    async def create_subdomain(hostname: str, ip: str, tld_config: dict):
        """Create subdomain using Cloudflare API similar to the Node.js function"""
        zone = tld_config["zone"]
        apitoken = tld_config["apitoken"] 
        tld = tld_config["tld"]
        
        # Clean hostname and IP
        clean_hostname = re.sub(r'[^a-z0-9.-]', '', hostname.lower())
        clean_ip = re.sub(r'[^0-9.]', '', ip)
        
        # Validate IP address
        try:
            ipaddress.IPv4Address(clean_ip)
        except:
            return {"success": False, "error": "Invalid IP address"}
        
        try:
            async with httpx.AsyncClient() as client:
                # Create main subdomain record
                main_record_name = f"{clean_hostname}.{tld}"
                main_response = await client.post(
                    f"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records",
                    headers={
                        "Authorization": f"Bearer {apitoken}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "type": "A",
                        "name": main_record_name,
                        "content": clean_ip,
                        "ttl": 3600,
                        "priority": 10,
                        "proxied": False
                    }
                )
                
                main_data = main_response.json()
                
                if not main_data.get("success"):
                    error_msg = str(main_data.get("errors", [{}])[0].get("message", "Unknown error"))
                    return {"success": False, "error": error_msg}
                
                # Create node subdomain record
                node_record_name = f"node.{clean_hostname}.{tld}"
                node_response = await client.post(
                    f"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records",
                    headers={
                        "Authorization": f"Bearer {apitoken}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "type": "A", 
                        "name": node_record_name,
                        "content": clean_ip,
                        "ttl": 3600,
                        "priority": 10,
                        "proxied": False
                    }
                )
                
                node_data = node_response.json()
                
                if not node_data.get("success"):
                    # If node record fails, try to cleanup main record
                    try:
                        await client.delete(
                            f"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records/{main_data['result']['id']}",
                            headers={"Authorization": f"Bearer {apitoken}"}
                        )
                    except:
                        pass
                    
                    error_msg = str(node_data.get("errors", [{}])[0].get("message", "Node subdomain creation failed"))
                    return {"success": False, "error": error_msg}
                
                return {
                    "success": True,
                    "zone": tld,
                    "main_subdomain": main_record_name,
                    "node_subdomain": node_record_name,
                    "ip": clean_ip
                }
                
        except Exception as e:
            return {"success": False, "error": str(e)}

# API Routes
@api_router.post("/auth/login")
async def login(user_data: UserLogin):
    user = await db.users.find_one({"email": user_data.email, "role": user_data.role})
    
    if not user or user["password"] != user_data.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_access_token(data={"sub": user["email"], "role": user["role"]})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": User(**user)
    }

@api_router.post("/users", dependencies=[Depends(get_current_user)])
async def create_user(user_data: UserCreate, current_user: User = Depends(get_current_user)):
    # Check permissions
    if current_user.role == "user":
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    if current_user.role == "reseller" and user_data.role != "user":
        raise HTTPException(status_code=403, detail="Resellers can only create regular users")
    
    # Check if user exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    
    user = User(**user_data.dict())
    await db.users.insert_one(user.dict())
    return {"message": "User created successfully", "user": user}

@api_router.get("/users")
async def list_users(current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    users = await db.users.find().to_list(length=None)
    return [User(**user) for user in users]

@api_router.post("/subdomains")
async def create_subdomain(subdomain_data: SubdomainCreate, current_user: User = Depends(get_current_user)):
    # Get TLD configuration
    tld_config = CLOUDFLARE_SETTINGS.get(subdomain_data.tld_id)
    if not tld_config:
        raise HTTPException(status_code=400, detail="Invalid TLD selection")
    
    # Check if subdomain already exists
    full_subdomain = f"{subdomain_data.hostname}.{tld_config['tld']}"
    existing = await db.subdomains.find_one({"subdomain": full_subdomain})
    if existing:
        raise HTTPException(status_code=400, detail="Subdomain already exists")
    
    # Create subdomain via Cloudflare API
    result = await CloudflareService.create_subdomain(
        subdomain_data.hostname,
        subdomain_data.ip_address,
        tld_config
    )
    
    if not result["success"]:
        raise HTTPException(status_code=400, detail=f"Failed to create subdomain: {result['error']}")
    
    # Save to database
    subdomain = Subdomain(
        user_email=current_user.email,
        hostname=subdomain_data.hostname,
        ip_address=subdomain_data.ip_address,
        tld=tld_config["tld"],
        subdomain=result["main_subdomain"],
        node_subdomain=result["node_subdomain"]
    )
    
    await db.subdomains.insert_one(subdomain.dict())
    
    return {
        "message": "Subdomain created successfully",
        "subdomain": result["main_subdomain"],
        "node_subdomain": result["node_subdomain"],
        "data": subdomain
    }

@api_router.get("/subdomains")
async def list_subdomains(current_user: User = Depends(get_current_user)):
    if current_user.role == "user":
        # Users only see their own subdomains
        subdomains = await db.subdomains.find({"user_email": current_user.email}).to_list(length=None)
    elif current_user.role == "reseller":
        # Resellers see subdomains of users they created + their own
        user_emails = [current_user.email]
        users = await db.users.find({"role": "user"}).to_list(length=None)
        user_emails.extend([user["email"] for user in users])
        subdomains = await db.subdomains.find({"user_email": {"$in": user_emails}}).to_list(length=None)
    else:
        # Admins see all subdomains
        subdomains = await db.subdomains.find().to_list(length=None)
    
    return [Subdomain(**subdomain) for subdomain in subdomains]

@api_router.get("/settings/tlds")
async def get_tlds():
    """Get available TLD options"""
    return [
        {"id": key, "tld": config["tld"]}
        for key, config in CLOUDFLARE_SETTINGS.items()
    ]

@api_router.get("/")
async def root():
    return {"message": "Website Subdomain Reseller API"}

# Include router
app.include_router(api_router)

# Initialize database with sample data
@app.on_event("startup")
async def startup_event():
    logger.info("Starting Website Subdomain Reseller API")
    
    # Create initial users if they don't exist
    admin_user = await db.users.find_one({"email": "admin@example.com"})
    if not admin_user:
        admin = User(
            email="admin@example.com",
            password="admin123",
            nama="Administrator",
            role=UserRole.ADMIN
        )
        await db.users.insert_one(admin.dict())
        logger.info("Created admin user")
    
    reseller_user = await db.users.find_one({"email": "reseller@example.com"})  
    if not reseller_user:
        reseller = User(
            email="reseller@example.com",
            password="reseller123", 
            nama="Reseller User",
            role=UserRole.RESELLER
        )
        await db.users.insert_one(reseller.dict())
        logger.info("Created reseller user")
    
    # Create sample regular users
    user1 = await db.users.find_one({"email": "user1@example.com"})
    if not user1:
        user = User(
            email="user1@example.com",
            password="user123",
            nama="Regular User 1", 
            role=UserRole.USER
        )
        await db.users.insert_one(user.dict())
        
    user2 = await db.users.find_one({"email": "user2@example.com"})
    if not user2:
        user = User(
            email="user2@example.com", 
            password="user123",
            nama="Regular User 2",
            role=UserRole.USER
        )
        await db.users.insert_one(user.dict())
        logger.info("Created sample users")

@app.on_event("shutdown")
async def shutdown_event():
    client.close()
    logger.info("Shutting down API")