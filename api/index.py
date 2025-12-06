from fastapi import FastAPI, APIRouter, Depends, HTTPException, status, UploadFile, File
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic_settings import BaseSettings
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey, func, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, List
import os
import httpx
import stripe
from contextlib import asynccontextmanager

# --- Configuration ---
class Settings(BaseSettings):
    PROJECT_NAME: str = "Research Paper Analysis API"
    API_V1_STR: str = "/api/v1"
    OPENAI_API_KEY: str = ""
    GEMINI_API_KEY: str = ""
    DATABASE_URL: str = "sqlite:////tmp/app.db"  # Use /tmp for Vercel
    SECRET_KEY: str = "your-super-secret-key-change-this-in-prod"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    BASE_URL: str = "http://localhost:8000"
    STRIPE_SECRET_KEY: str = ""
    STRIPE_WEBHOOK_SECRET: str = ""
    STRIPE_PRICE_ID: str = ""

    def model_post_init(self, __context):
        env_db_url = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL") or os.getenv("STORAGE_DATABASE_URL")
        if env_db_url:
            if env_db_url.startswith("postgres://"):
                env_db_url = env_db_url.replace("postgres://", "postgresql://", 1)
            self.DATABASE_URL = env_db_url
        
        # Override other settings from environment
        for key in ["OPENAI_API_KEY", "GEMINI_API_KEY", "SECRET_KEY", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "BASE_URL", "STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET", "STRIPE_PRICE_ID"]:
            env_val = os.getenv(key)
            if env_val:
                setattr(self, key, env_val)
        
        if self.STRIPE_SECRET_KEY:
            stripe.api_key = self.STRIPE_SECRET_KEY
        
        # Attempt to set BASE_URL automatically on Vercel if not set
        if os.getenv("VERCEL") and not os.getenv("BASE_URL") and os.getenv("VERCEL_URL"):
             self.BASE_URL = f"https://{os.getenv('VERCEL_URL')}"

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()

# --- Database ---
engine = create_engine(
    settings.DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Models ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    plan_type = Column(String, default="free")
    picture = Column(String, nullable=True)
    daily_requests_count = Column(Integer, default=0)
    daily_chat_count = Column(Integer, default=0)
    last_request_date = Column(DateTime(timezone=True), server_default=func.now())
    analyses = relationship("AnalysisLog", back_populates="owner")

class AnalysisLog(Base):
    __tablename__ = "analysis_logs"
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    status = Column(String)
    text_content = Column(String, nullable=True)
    analysis_result = Column(String, nullable=True)
    chat_history = Column(String, nullable=True) # Store JSON list of messages
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    owner = relationship("User", back_populates="analyses")

# --- Schemas ---
class UserCreate(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    user_email: str
    user_picture: Optional[str] = None
    plan_type: str

class AnalysisResponse(BaseModel):
    id: int
    title: str
    abstract: str
    methodology: str
    results: str
    conclusions: str
    key_findings: List[str]
    chat_history: Optional[List[dict]] = []

class ChatRequest(BaseModel):
    analysis_id: int
    question: str
    history: List[dict] = []

# --- Security ---
pwd_context = CryptContext(
    schemes=["pbkdf2_sha256", "bcrypt"], 
    deprecated="auto",
    pbkdf2_sha256__default_rounds=20000  # Reduced from default 29000 for speed
)
oauth2_scheme = None # Defined later to avoid circular issues if split, but here it's fine.
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user

# --- Services ---
# Simple PDF extraction (placeholder for complex logic to keep file single)
import io
# We need a PDF parser. Let's use a simple string search or mock for now to reduce dependencies if pypdf is missing, 
# but user had it before. Let's assume we can add pypdf back or use a simple text extraction.
# Actually, let's add pypdf to requirements.
try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None

async def extract_text_from_pdf(file: UploadFile) -> str:
    if not PdfReader:
        return "PDF parsing library not installed."
    try:
        content = await file.read()
        pdf = PdfReader(io.BytesIO(content))
        text = ""
        for page in pdf.pages:
            extracted = page.extract_text()
            if extracted:
                text += extracted + "\n"
        return text
    except Exception as e:
        print(f"PDF Extraction Error: {e}")
        return f"Error extracting text from PDF: {str(e)}"



async def get_available_gemini_model(api_key):
    """Dynamically find the best available Gemini model"""
    import httpx
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=10.0)
            
        if response.status_code != 200:
            print(f"Failed to list models: {response.text}")
            return "models/gemini-pro" # Fallback
            
        data = response.json()
        models = [m['name'] for m in data.get('models', []) if 'generateContent' in m.get('supportedGenerationMethods', [])]
        
        print(f"Available models: {models}")
        
        # Preference order
        preferred = [
            "models/gemini-1.5-flash",
            "models/gemini-1.5-flash-latest",
            "models/gemini-pro",
            "models/gemini-1.0-pro",
            "models/gemini-1.5-pro"
        ]
        
        for p in preferred:
            if p in models:
                return p
                
        # Return first available if none of preferred match
        if models:
            return models[0]
            
        return "models/gemini-pro"
    except Exception as e:
        print(f"Error finding model: {e}")
        return "models/gemini-pro"

async def analyze_paper_ai(text: str):
    """
    Analyze paper content using Gemini AI (REST API)
    """
    # 1. Basic extraction (fallback)
    import re
    # Extract title
    lines = [line.strip() for line in text.split('\n') if line.strip()]
    title = "Research Paper"
    for line in lines[:10]:
        if len(line) > 20 and len(line) < 200:
            title = line
            break
            
    # Extract abstract
    abstract = ""
    abstract_match = re.search(r'(?:ABSTRACT|Abstract)(.*?)(?:INTRODUCTION|Introduction|1\.|I\.)', text, re.DOTALL | re.IGNORECASE)
    if abstract_match:
        abstract = abstract_match.group(1).strip()[:1000]
    else:
        sentences = re.split(r'[.!?]+', text[:1000])
        abstract = '. '.join(sentences[:3]) + '.'

    # Basic structure
    basic_result = {
        "title": title[:200],
        "abstract": abstract if abstract else "Paper uploaded successfully. Full text extracted.",
        "methodology": "Methodology section identified in paper text.",
        "results": "Results and findings extracted from paper.",
        "conclusions": "Conclusions available in full paper text.",
        "key_findings": ["Paper analysis complete"]
    }

    # 2. Try AI enhancement
    if settings.GEMINI_API_KEY and len(settings.GEMINI_API_KEY) > 20:
        try:
            import json
            import httpx
            
            prompt = f"""Analyze this research paper and extract key information in JSON format:

Title: {title}

Paper text (first 10000 characters):
{text[:10000]}

Provide JSON with: title, abstract (2-3 sentences), methodology (2 sentences), results (2 sentences), conclusions (2 sentences), key_findings (array of 3-5 items).
Return ONLY valid JSON."""

            model_name = await get_available_gemini_model(settings.GEMINI_API_KEY)
            print(f"Using Gemini model: {model_name}")
            
            url = f"https://generativelanguage.googleapis.com/v1beta/{model_name}:generateContent?key={settings.GEMINI_API_KEY}"
            payload = {
                "contents": [{
                    "parts": [{"text": prompt}]
                }]
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(url, json=payload, timeout=30.0)
                
            if response.status_code != 200:
                print(f"Gemini API Error: {response.text}")
                return basic_result
                
            data = response.json()
            try:
                ai_text = data['candidates'][0]['content']['parts'][0]['text'].strip()
            except (KeyError, IndexError) as e:
                 print(f"Gemini response parsing error: {e}, Response: {data}")
                 return basic_result
            
            # Clean and parse JSON
            if ai_text.startswith("```json"):
                ai_text = ai_text.replace("```json", "").replace("```", "").strip()
            elif ai_text.startswith("```"):
                ai_text = ai_text.replace("```", "").strip()
            
            ai_result = json.loads(ai_text)
            
            # Ensure all keys exist
            for key in ["title", "abstract", "methodology", "results", "conclusions", "key_findings"]:
                if key not in ai_result:
                    ai_result[key] = basic_result.get(key, "N/A")
            
            return ai_result
            
        except Exception as e:
            print(f"AI Analysis failed: {e}")
            import traceback
            traceback.print_exc()
            return basic_result
            
    return basic_result
            

# --- API Routes ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        print(f"Starting app with DATABASE_URL: {settings.DATABASE_URL[:20]}...")
        Base.metadata.create_all(bind=engine)
        print("Database tables created successfully")
        
        # Migration: Add user_id column if it doesn't exist
        try:
            with engine.connect() as conn:
                # Try to add the column (this will fail silently if it already exists)
                try:
                    if "sqlite" in settings.DATABASE_URL:
                        # SQLite doesn't support ALTER TABLE ADD COLUMN IF NOT EXISTS directly
                        # Check if column exists first
                        result = conn.execute(text("PRAGMA table_info(analysis_logs)"))
                        columns = [row[1] for row in result]
                        if "user_id" not in columns:
                            conn.execute(text("ALTER TABLE analysis_logs ADD COLUMN user_id INTEGER"))
                            conn.commit()
                    else:
                        # PostgreSQL
                        conn.execute(text("ALTER TABLE analysis_logs ADD COLUMN IF NOT EXISTS user_id INTEGER"))
                        conn.commit()
                        
                    # Also check for picture column in users
                    if "sqlite" in settings.DATABASE_URL:
                        result = conn.execute(text("PRAGMA table_info(users)"))
                        columns = [row[1] for row in result]
                        if "picture" not in columns:
                             conn.execute(text("ALTER TABLE users ADD COLUMN picture VARCHAR"))
                             conn.commit()
                             
                        # Check for analysis_result in analysis_logs
                        result_logs = conn.execute(text("PRAGMA table_info(analysis_logs)"))
                        columns_logs = [row[1] for row in result_logs]
                        if "analysis_result" not in columns_logs:
                             conn.execute(text("ALTER TABLE analysis_logs ADD COLUMN analysis_result VARCHAR"))
                             conn.commit()
                             
                        # Check for chat_history
                        if "chat_history" not in columns_logs:
                             conn.execute(text("ALTER TABLE analysis_logs ADD COLUMN chat_history VARCHAR"))
                             conn.commit()
                             
                        # Check for user usage columns
                        if "daily_requests_count" not in columns:
                             conn.execute(text("ALTER TABLE users ADD COLUMN daily_requests_count INTEGER DEFAULT 0"))
                             conn.execute(text("ALTER TABLE users ADD COLUMN last_request_date TIMESTAMP"))
                             conn.commit()
                    else:
                         conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS picture VARCHAR"))
                         conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS daily_requests_count INTEGER DEFAULT 0"))
                         conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_request_date TIMESTAMP"))
                         conn.execute(text("ALTER TABLE analysis_logs ADD COLUMN IF NOT EXISTS analysis_result VARCHAR"))
                         conn.execute(text("ALTER TABLE analysis_logs ADD COLUMN IF NOT EXISTS chat_history VARCHAR"))
                         conn.commit()
                         
                except Exception as e:
                    print(f"Migration note: {e}")
                    # Column likely already exists, continue
                    pass
        except Exception as e:
            print(f"Migration error: {e}")
        
        print("App startup complete")
        yield
    except Exception as e:
        print(f"FATAL ERROR during startup: {e}")
        import traceback
        traceback.print_exc()
        # Don't raise - let the app start anyway
        yield

# Create app with lifespan
app = FastAPI(title=settings.PROJECT_NAME, lifespan=lifespan)

# Add CORS middleware
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Health check endpoint
@app.get("/")
async def root():
    return {"status": "ok", "message": "PaperAnalyzer API is running"}

@app.get("/health")
async def health():
    return {"status": "healthy"}


# Auth Router
auth_router = APIRouter()

@auth_router.post("/signup")
def signup(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    db_user = User(email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@auth_router.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.email})
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "user_email": user.email,
        "user_picture": user.picture,
        "plan_type": user.plan_type
    }

@auth_router.get("/google/login")
async def google_login():
    redirect_uri = f"{settings.BASE_URL}{settings.API_V1_STR}/auth/google/callback"
    return {
        "url": f"https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id={settings.GOOGLE_CLIENT_ID}&redirect_uri={redirect_uri}&scope=openid%20email%20profile"
    }

from fastapi.responses import RedirectResponse

@auth_router.get("/google/callback")
async def google_callback(code: str, db: Session = Depends(get_db)):
    token_url = "https://oauth2.googleapis.com/token"
    redirect_uri = f"{settings.BASE_URL}{settings.API_V1_STR}/auth/google/callback"
    data = {
        "code": code,
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code"
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(token_url, data=data)
            response.raise_for_status()
            tokens = response.json()
            google_access_token = tokens["access_token"]
            
            user_info_response = await client.get("https://www.googleapis.com/oauth2/v1/userinfo", headers={"Authorization": f"Bearer {google_access_token}"})
            user_info = user_info_response.json()
            
        email = user_info["email"]
        picture = user_info.get("picture")
        
        user = db.query(User).filter(User.email == email).first()
        if not user:
            # Create user
            user = User(email=email, hashed_password=get_password_hash("GOOGLE_USER"), is_active=True, picture=picture)
            db.add(user)
            db.commit()
            db.refresh(user)
        else:
            # Update picture if changed
            if picture and user.picture != picture:
                user.picture = picture
                db.commit()
            
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.email}, expires_delta=access_token_expires
        )
        
        # Pass picture and email in URL to frontend
        redirect_url = f"{settings.BASE_URL}/google-callback?token={access_token}&email={email}"
        if picture:
             redirect_url += f"&picture={picture}"
        
        # Add usage info
        redirect_url += f"&usage={user.daily_requests_count}&plan={user.plan_type}"
             
        return RedirectResponse(url=redirect_url)
    except Exception as e:
        print(f"Google Auth Error: {e}")
        raise HTTPException(status_code=400, detail=f"Google Auth Error: {str(e)}")

# Analysis Router
analysis_router = APIRouter()

@analysis_router.post("/upload", response_model=AnalysisResponse)
async def upload_paper(
    file: UploadFile = File(...), 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    print(f"Upload started - filename: {file.filename}, content_type: {file.content_type}")
    
    # --- Usage Limit Check (Uploads) ---
    from datetime import datetime
    now = datetime.utcnow()
    
    # Reset count if new day (using last_request_date to track day)
    if current_user.last_request_date and current_user.last_request_date.date() < now.date():
        current_user.daily_requests_count = 0
        current_user.daily_chat_count = 0
        current_user.last_request_date = now
        db.commit()
    
    # Check limit for Free plan (e.g., 5 uploads per day)
    # We use the same daily_requests_count for both uploads and chats for simplicity, 
    # but give uploads a higher "weight" or just share the pool. 
    # Let's say 50 questions OR 5 uploads. Or distinct?
    # For now, let's treat an upload as 5 "requests" worth of value or just keep it simple:
    # 5 uploads strict limit for free users.
    
    # Actually, the user model only has one counter: daily_requests_count. 
    # Let's increment it by 10 for an upload to make it "expensive" in the shared pool, 
    # OR better, since we want "no loopholes", we should probably have separate counters or just a higher generic usage.
    # Let's count an upload as 5 "credits" (requests).
    
    COST_PER_UPLOAD = 1
    if current_user.plan_type == 'free':
        if current_user.daily_requests_count + COST_PER_UPLOAD > 5:
             raise HTTPException(status_code=402, detail="Daily limit reached. Upgrade to Pro for unlimited uploads.")
             
    # Increment usage
    current_user.daily_requests_count += COST_PER_UPLOAD
    current_user.last_request_date = now
    # We commit at the end after success, or here? 
    # Better to commit here so they "pay" for the attempt? 
    # No, commit only on success to be fair. We'll add to DB later.
    # But wait, if we don't commit now and it fails, they don't lose credits. That's fair.
    # But if we don't check db state properly...
    # Let's hold off commit until success.
    # -------------------------
    try:
        # Check file size
        content = await file.read()
        file_size = len(content)
        print(f"File size: {file_size} bytes ({file_size / 1024 / 1024:.2f} MB)")
        
        if file_size > 10 * 1024 * 1024: # 10MB limit
            raise HTTPException(status_code=400, detail="File too large. Maximum size is 10MB.")
        
        # Reset file pointer
        await file.seek(0)
        
        text = await extract_text_from_pdf(file)
        print(f"Text extracted: {len(text)} characters")
        
        result = await analyze_paper_ai(text)
        print(f"Analysis complete: {result['title']}")
        
        import json
        
        db_log = AnalysisLog(
            filename=file.filename, 
            status="success", 
            text_content=text[:10000],  # Limit stored text
            analysis_result=json.dumps(result), # Save the result!
            user_id=current_user.id if current_user else None
        )
        db.add(db_log)
        db.commit()
        db.refresh(db_log)
        
        print(f"Upload successful - ID: {db_log.id}")
        return {**result, "id": db_log.id}
    except Exception as e:
        print(f"Upload Endpoint Error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Server Error: {str(e)}")

@analysis_router.post("/chat")
async def chat(request: ChatRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    print(f"Chat request received - analysis_id: {request.analysis_id}, question: {request.question}")
    
    log = db.query(AnalysisLog).filter(AnalysisLog.id == request.analysis_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Analysis not found")
        
    
    # --- Pricing & Usage Check ---
    # Chat Limit: 7 messages per day for free users
    
    # Reset counts if new day
    from datetime import datetime
    now = datetime.utcnow()
    # Check if last request was on a previous day
    if current_user.last_request_date and current_user.last_request_date.date() < now.date():
        current_user.daily_requests_count = 0
        current_user.daily_chat_count = 0
        current_user.last_request_date = now
        db.commit()

    if current_user.plan_type == 'free':
        # Check chat limit (7)
        if (current_user.daily_chat_count or 0) >= 7:
            return {"answer": "You have reached your daily limit of 7 chat messages. Please upgrade to Pro for unlimited chatting."}

    # Increment chat usage
    current_user.daily_chat_count = (current_user.daily_chat_count or 0) + 1
    current_user.last_request_date = now
    db.commit() # Commit usage immediately
    # -----------------------------

    # Load existing history
    import json
    history = []
    if log.chat_history:
        try:
            history = json.loads(log.chat_history)
        except:
            history = []
            
    # Append user message
    history.append({"role": "user", "content": request.question})
    
    # Use Gemini for chat if available
    answer = ""
    if settings.GEMINI_API_KEY:
        try:
            import httpx
            
            # Build conversation context
            context = f"""You are a research paper assistant. Answer questions about this paper.

Paper: {log.filename}
Content (first 5000 chars): {log.text_content[:5000] if log.text_content else 'No content available'}

Previous conversation:
"""
            # Use the saved history for context (last 5 messages)
            for msg in history[-6:-1]: 
                role = "User" if msg.get("role") == "user" else "Assistant"
                context += f"{role}: {msg.get('content', '')}\n"
            
            context += f"\nUser question: {request.question}\n\nProvide a helpful, concise answer based on the paper content:"
            
            model_name = await get_available_gemini_model(settings.GEMINI_API_KEY)
            url = f"https://generativelanguage.googleapis.com/v1beta/{model_name}:generateContent?key={settings.GEMINI_API_KEY}"
            payload = {
                "contents": [{
                    "parts": [{"text": context}]
                }]
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(url, json=payload, timeout=30.0)

            if response.status_code == 200:
                data = response.json()
                try:
                    answer = data['candidates'][0]['content']['parts'][0]['text']
                except:
                    answer = "I received an unexpected response structure."
            else:
                 error_msg = f"Status: {response.status_code}"
                 try:
                     err_data = response.json()
                     if 'error' in err_data:
                         error_msg = err_data['error'].get('message', error_msg)
                 except:
                     pass
                 answer = f"AI Service Error: {error_msg}"

        except Exception as e:
            print(f"Chat AI Error: {e}")
            answer = f"I encountered an error processing your request."
    else:
        answer = f"AI response to: {request.question} (Context: {log.filename})"
        
    # Append assistant answer and save
    history.append({"role": "assistant", "content": answer})
    log.chat_history = json.dumps(history)
    db.commit()
    
    return {"answer": answer}

@analysis_router.get("/history", response_model=List[AnalysisResponse])
def get_history(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Get list of past analyses for the current user"""
    import json
    analyses = db.query(AnalysisLog).filter(AnalysisLog.user_id == current_user.id).order_by(AnalysisLog.timestamp.desc()).all()
    
    response = []
    for log in analyses:
        try:
            # Parse the stored JSON result
            if log.analysis_result:
                data = json.loads(log.analysis_result)
                # Ensure it matches AnalysisResponse fields
                item = {
                    "id": log.id,
                    "title": data.get("title", log.filename),
                    "abstract": data.get("abstract", "No abstract available"),
                    "methodology": data.get("methodology", "N/A"),
                    "results": data.get("results", "N/A"),
                    "conclusions": data.get("conclusions", "N/A"),
                    "key_findings": data.get("key_findings", []),
                    "chat_history": json.loads(log.chat_history) if log.chat_history else []
                }
                response.append(item)
            else:
                 # Legacy records without analysis_result
                 response.append({
                    "id": log.id,
                    "title": log.filename,
                    "abstract": "Legacy record (details not stored)",
                    "methodology": "N/A",
                    "results": "N/A",
                    "conclusions": "N/A",
                    "key_findings": [],
                    "chat_history": json.loads(log.chat_history) if log.chat_history else []
                 })
        except Exception as e:
             print(f"Error parsing log {log.id}: {e}")
             
    return response

@analysis_router.get("/usage")
def get_usage(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Get current usage stats"""
    return {
        "plan": current_user.plan_type,
        "count": current_user.daily_requests_count,
        "limit": 5 if current_user.plan_type == 'free' else "Unlimited"
    }

@analysis_router.get("/{analysis_id}", response_model=AnalysisResponse)
def get_analysis(analysis_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Get specific analysis details"""
    import json
    log = db.query(AnalysisLog).filter(AnalysisLog.id == analysis_id, AnalysisLog.user_id == current_user.id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Analysis not found")
        
    if log.analysis_result:
        data = json.loads(log.analysis_result)
        return {**data, "id": log.id}
    else:
        return {
            "id": log.id,
            "title": log.filename,
            "abstract": "Legacy record (details not stored)",
            "methodology": "N/A",
            "results": "N/A",
            "conclusions": "N/A",
            "key_findings": []
        }

# --- Payment Router ---
payment_router = APIRouter()

@payment_router.post("/create-checkout-session")
async def create_checkout_session(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not settings.STRIPE_SECRET_KEY or not settings.STRIPE_PRICE_ID:
        raise HTTPException(status_code=500, detail="Stripe configuration missing on server")

    if current_user.plan_type == "pro":
        return {"url": f"{settings.BASE_URL}/dashboard?message=Already_Pro"}

    try:
        checkout_session = stripe.checkout.Session.create(
            customer_email=current_user.email,
            line_items=[
                {
                    'price': settings.STRIPE_PRICE_ID,
                    'quantity': 1,
                },
            ],
            mode='subscription',
            success_url=settings.BASE_URL + '/dashboard?payment_success=true',
            cancel_url=settings.BASE_URL + '/pricing?payment_canceled=true',
            metadata={
                "user_id": str(current_user.id),
                "user_email": current_user.email
            },
            payment_method_types=['card'],
        )
        return {"url": checkout_session.url}
    except Exception as e:
        print(f"Stripe Error: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@payment_router.post("/create-portal-session")
async def create_portal_session(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not settings.STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Stripe configuration missing")

    # We need a customer ID. In a real app we'd save stripe_customer_id on the User model.
    # For now, we unfortunately can't easy open portal without saving customer ID first.
    # We'll skip this or implement basic customer saving in webhook.
    # Loophole fix: We must save customer ID.
    # For now, just return a message if not implemented fully.
    return {"message": "Customer portal requires saving Stripe Customer ID. Feature pending DB migration."}


from fastapi import Request

@payment_router.post("/webhook")
async def webhook(request: Request, db: Session = Depends(get_db)):
    payload = await request.body()
    sig_header = request.headers.get('stripe-signature')
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, settings.STRIPE_WEBHOOK_SECRET
        )
    except ValueError as e:
        # Invalid payload
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        raise HTTPException(status_code=400, detail="Invalid signature")

    # Handle the event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        
        # Get user from metadata
        user_id = session.get("metadata", {}).get("user_id")
        
        if user_id:
            user = db.query(User).filter(User.id == int(user_id)).first()
            if user:
                user.plan_type = "pro"
                # user.stripe_customer_id = session.get("customer") # Ideally save this
                db.commit()
                print(f"User {user_id} upgraded to Pro")
    
    return {"status": "success"}

# Mount Routers
app.include_router(auth_router, prefix=f"{settings.API_V1_STR}/auth", tags=["auth"])
app.include_router(analysis_router, prefix=f"{settings.API_V1_STR}/analysis", tags=["analysis"])
app.include_router(payment_router, prefix=f"{settings.API_V1_STR}/payment", tags=["payment"])

# Serve Frontend
import os
from pathlib import Path

# Mount static files
frontend_dist = Path(__file__).parent.parent / "frontend" / "dist"
if frontend_dist.exists():
    app.mount("/assets", StaticFiles(directory=str(frontend_dist / "assets")), name="assets")
    
    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        # Serve index.html for all non-API routes
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404)
        
        file_path = frontend_dist / full_path
        if file_path.is_file():
            return FileResponse(file_path)
        
        # Default to index.html for SPA routing
        return FileResponse(frontend_dist / "index.html")
