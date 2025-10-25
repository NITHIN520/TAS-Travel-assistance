import os
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import requests
from dotenv import load_dotenv
from datetime import datetime, timedelta
import random
from news import router as news_router
from motor.motor_asyncio import AsyncIOMotorClient
from argon2 import PasswordHasher
import jwt

# Load environment variables
load_dotenv()
api_key = os.environ.get('google_cloud')
MONGODB_URI = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017')
DB_NAME = os.environ.get('DB_NAME', 'monsoon')
JWT_SECRET = os.environ.get('JWT_SECRET', 'dev-secret-change-me')
JWT_ALG = 'HS256'

app = FastAPI()

# Configure CORS to allow requests from any origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# Include the news router
app.include_router(news_router, prefix="/api")

class RouteRequest(BaseModel):
    origin: str
    destination: str
    avoid_tolls: bool = False
    avoid_highways: bool = False
    avoid_flooded: bool = False

class RouteData(BaseModel):
    polyline: str
    distance: str
    duration: str
    risk_score: Optional[float] = None  # 0 (safe) to 1 (high risk)
    risk_level: Optional[str] = None    # Low/Medium/High

class TrafficData(BaseModel):
    time: str
    trafficLevel: float
    duration: int

class ReportItem(BaseModel):
    id: Optional[str] = None
    type: str  # e.g., waterlogging, tree_fall, pothole
    severity: str  # Low/Medium/High
    lat: float
    lng: float
    notes: Optional[str] = None
    timestamp: Optional[str] = None

REPORTS_FILE = "reports.json"

def load_reports() -> List[dict]:
    try:
        import json, os
        if os.path.exists(REPORTS_FILE):
            with open(REPORTS_FILE, 'r') as f:
                return json.load(f)
        return []
    except Exception:
        return []

def save_reports(reports: List[dict]) -> None:
    import json
    with open(REPORTS_FILE, 'w') as f:
        json.dump(reports, f, indent=2)

# -------------------------
# MongoDB and Auth (Users)
# -------------------------

ph = PasswordHasher()
mongo_client: Optional[AsyncIOMotorClient] = None
db = None

class UserCreate(BaseModel):
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class UserUpdate(BaseModel):
    password: Optional[str] = None
    roles: Optional[List[str]] = None

class UserOut(BaseModel):
    id: str
    email: str
    roles: List[str] = []

def user_out_from_doc(doc: dict) -> UserOut:
    return UserOut(id=str(doc.get('_id')), email=doc.get('email', ''), roles=doc.get('roles', []) )

async def get_db():
    return db

def create_jwt(payload: dict) -> str:
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def verify_jwt(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])

async def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.lower().startswith('bearer '):
        raise HTTPException(status_code=401, detail='Missing or invalid Authorization header')
    token = authorization.split(' ', 1)[1]
    try:
        payload = verify_jwt(token)
    except Exception:
        raise HTTPException(status_code=401, detail='Invalid token')
    users = db['users']
    user = await users.find_one({'_id': payload.get('uid')})
    if not user:
        raise HTTPException(status_code=401, detail='User not found')
    return user

@app.on_event('startup')
async def on_startup():
    global mongo_client, db
    mongo_client = AsyncIOMotorClient(MONGODB_URI)
    db = mongo_client[DB_NAME]
    # indexes
    await db['users'].create_index('email', unique=True)

@app.on_event('shutdown')
async def on_shutdown():
    if mongo_client:
        mongo_client.close()

@app.post('/api/auth/signup', response_model=UserOut)
async def signup(user: UserCreate):
    users = db['users']
    try:
        password_hash = ph.hash(user.password)
        doc = {
            'email': user.email.lower().strip(),
            'passwordHash': password_hash,
            'roles': [],
            'createdAt': datetime.utcnow().isoformat()
        }
        result = await users.insert_one(doc)
        doc['_id'] = result.inserted_id
        return user_out_from_doc(doc)
    except Exception as e:
        # Likely duplicate email
        raise HTTPException(status_code=400, detail='Signup failed: possibly duplicate email')

@app.post('/api/auth/login')
async def login(creds: UserLogin):
    users = db['users']
    doc = await users.find_one({'email': creds.email.lower().strip()})
    if not doc:
        raise HTTPException(status_code=401, detail='Invalid credentials')
    try:
        ph.verify(doc.get('passwordHash', ''), creds.password)
    except Exception:
        raise HTTPException(status_code=401, detail='Invalid credentials')
    token = create_jwt({'uid': doc['_id']})
    return {'token': token, 'user': user_out_from_doc(doc)}

@app.get('/api/users', response_model=List[UserOut])
async def list_users(current=Depends(get_current_user)):
    users = db['users']
    items = []
    async for doc in users.find({}, {'passwordHash': 0}):
        items.append(user_out_from_doc(doc))
    return items

@app.post('/api/users', response_model=UserOut)
async def create_user(user: UserCreate, current=Depends(get_current_user)):
    users = db['users']
    password_hash = ph.hash(user.password)
    doc = {
        'email': user.email.lower().strip(),
        'passwordHash': password_hash,
        'roles': [],
        'createdAt': datetime.utcnow().isoformat()
    }
    try:
        result = await users.insert_one(doc)
        doc['_id'] = result.inserted_id
        return user_out_from_doc(doc)
    except Exception:
        raise HTTPException(status_code=400, detail='Create user failed')

@app.patch('/api/users/{user_id}', response_model=UserOut)
async def update_user(user_id: str, payload: UserUpdate, current=Depends(get_current_user)):
    from bson import ObjectId
    users = db['users']
    update: dict = {}
    if payload.password:
        update['passwordHash'] = ph.hash(payload.password)
    if payload.roles is not None:
        update['roles'] = payload.roles
    if not update:
        raise HTTPException(status_code=400, detail='Nothing to update')
    result = await users.find_one_and_update({'_id': ObjectId(user_id)}, {'$set': update}, return_document=True)
    if not result:
        raise HTTPException(status_code=404, detail='User not found')
    return user_out_from_doc(result)

@app.delete('/api/users/{user_id}')
async def delete_user(user_id: str, current=Depends(get_current_user)):
    from bson import ObjectId
    users = db['users']
    result = await users.delete_one({'_id': ObjectId(user_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail='User not found')
    return {'ok': True}

def haversine_distance_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    from math import radians, cos, sin, asin, sqrt
    R = 6371000.0
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat/2)**2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon/2)**2
    c = 2 * asin(sqrt(a))
    return R * c

def decode_polyline(encoded: str) -> List[List[float]]:
    if not encoded:
        return []
    points = []
    index = 0
    lat = 0
    lng = 0
    while index < len(encoded):
        b = 0
        shift = 0
        result = 0
        while True:
            b = ord(encoded[index]) - 63
            index += 1
            result |= (b & 0x1f) << shift
            shift += 5
            if b < 0x20:
                break
        dlat = ~(result >> 1) if (result & 1) else (result >> 1)
        lat += dlat
        shift = 0
        result = 0
        while True:
            b = ord(encoded[index]) - 63
            index += 1
            result |= (b & 0x1f) << shift
            shift += 5
            if b < 0x20:
                break
        dlng = ~(result >> 1) if (result & 1) else (result >> 1)
        lng += dlng
        points.append([lat / 1e5, lng / 1e5])
    # return as [ [lat, lng], ... ]
    return points

def compute_route_risk(polyline_encoded: str, reports: List[dict]) -> float:
    # Consider only recent and relevant reports
    recent_cutoff = datetime.utcnow() - timedelta(hours=12)
    relevant = []
    for r in reports:
        if r.get('type', '').lower() in ['waterlogging', 'flood', 'flooding', 'water_log']:
            try:
                ts = datetime.fromisoformat(r.get('timestamp'))
            except Exception:
                ts = recent_cutoff  # include if timestamp malformed
            if ts >= recent_cutoff:
                relevant.append(r)
    if not relevant:
        return 0.0
    path = decode_polyline(polyline_encoded)
    if not path:
        return 0.0
    # Risk based on minimum distance to any relevant report along path
    min_distance_m = float('inf')
    for lat, lng in path:
        for r in relevant:
            d = haversine_distance_m(lat, lng, float(r['lat']), float(r['lng']))
            if d < min_distance_m:
                min_distance_m = d
    # Map distance to risk (<=100m => 1, >=500m => 0)
    if min_distance_m == float('inf'):
        return 0.0
    if min_distance_m <= 100:
        return 1.0
    if min_distance_m >= 500:
        return 0.0
    # Linear interpolation between 100m and 500m
    return max(0.0, min(1.0, (500 - min_distance_m) / 400))

@app.post("/api/routes", response_model=List[RouteData])
def get_routes(request: RouteRequest):
    url = "https://routes.googleapis.com/directions/v2:computeRoutes"
    
    headers = {
        "Content-Type": "application/json",
        "X-Goog-Api-Key": api_key,
        "X-Goog-FieldMask": "routes.duration,routes.distanceMeters,routes.polyline.encodedPolyline,routes.routeLabels,routes.staticDuration"
    }
    
    data = {
        "origin": {
            "address": request.origin
        },
        "destination": {
            "address": request.destination
        },
        "travelMode": "DRIVE",
        "routingPreference": "TRAFFIC_AWARE",
        "computeAlternativeRoutes": True,
        "routeModifiers": {
            "avoidTolls": request.avoid_tolls,
            "avoidHighways": request.avoid_highways,
            "avoidFerries": False
        },
        "languageCode": "en-US",
        "units": "METRIC"  # Using metric for km instead of miles
    }
    
    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()  # Raise exception if the request failed
        
        result = response.json()
        routes_data = []
        reports = load_reports()
        
        for route in result.get("routes", []):
            # Convert meters to km and format to 1 decimal place
            distance_km = round(route.get("distanceMeters", 0) / 1000, 1)
            
            # Convert seconds to minutes
            duration_seconds = int(route.get("duration", "0").rstrip("s"))
            duration_minutes = round(duration_seconds / 60)
            
            encoded_polyline = route.get("polyline", {}).get("encodedPolyline", "")
            risk = compute_route_risk(encoded_polyline, reports)
            risk_level = (
                "High" if risk >= 0.66 else
                "Medium" if risk >= 0.33 else
                "Low"
            )
            routes_data.append(
                RouteData(
                    polyline=encoded_polyline,
                    distance=f"{distance_km} km",
                    duration=f"{duration_minutes} mins",
                    risk_score=round(risk, 2),
                    risk_level=risk_level
                )
            )
        
        # Optionally filter if user wants to avoid flooded roads
        if request.avoid_flooded:
            filtered = [r for r in routes_data if (r.risk_score or 0) < 0.33]
            if filtered:
                return filtered
            # If none are safe enough, return original but sorted by lowest risk first
        # Sort by risk ascending so safest first
        routes_data.sort(key=lambda r: (r.risk_score or 0))
        return routes_data
    
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Error fetching routes: {str(e)}")

@app.get("/api/traffic/{route_index}", response_model=List[TrafficData])
def get_traffic_data(route_index: int, origin: str, destination: str):
    try:
        # Generate traffic data for the next 24 hours in 30-minute intervals
        traffic_data = []
        current_time = datetime.now()
        
        for i in range(48):  # 24 hours * 2 (30-minute intervals)
            # Calculate time for this interval
            interval_time = current_time + timedelta(minutes=i * 30)
            
            # Generate traffic level (0-100%)
            # This is a simplified example - in a real app, you'd use actual traffic data
            hour = interval_time.hour
            if 7 <= hour <= 9 or 17 <= hour <= 19:  # Rush hours
                traffic_level = random.uniform(70, 100)
            elif 10 <= hour <= 16:  # Midday
                traffic_level = random.uniform(40, 70)
            else:  # Night/early morning
                traffic_level = random.uniform(10, 40)
            
            # Calculate duration based on traffic level
            base_duration = 30  # Base duration in minutes
            duration = int(base_duration * (1 + (traffic_level / 100)))
            
            traffic_data.append({
                "time": interval_time.strftime("%H:%M"),
                "trafficLevel": round(traffic_level, 1),
                "duration": duration
            })
        
        return traffic_data
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating traffic data: {str(e)}")

@app.get("/api/reports", response_model=List[ReportItem])
def get_reports() -> List[ReportItem]:
    reports = load_reports()
    return reports

@app.post("/api/reports", response_model=ReportItem)
def create_report(report: ReportItem) -> ReportItem:
    reports = load_reports()
    # assign id and timestamp
    report_dict = report.model_dump()
    report_dict["id"] = report_dict.get("id") or f"r_{int(datetime.utcnow().timestamp()*1000)}"
    report_dict["timestamp"] = report_dict.get("timestamp") or datetime.utcnow().isoformat()
    reports.append(report_dict)
    save_reports(reports)
    return report_dict

# For testing purposes
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)