import os, secrets, hashlib, smtplib, ssl
from datetime import datetime, timezone, timedelta
from email.message import EmailMessage
from fastapi import APIRouter, HTTPException, Request, Response, Depends
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import Column, String, DateTime, Boolean, create_engine, select
from sqlalchemy.orm import declarative_base, sessionmaker
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from pwdlib import PasswordHash

DATABASE_URL=os.getenv('DATABASE_URL','sqlite:///./storage/gt_empower.db')
engine=create_engine(DATABASE_URL,connect_args={'check_same_thread':False} if DATABASE_URL.startswith('sqlite') else {},pool_pre_ping=True)
Session=sessionmaker(bind=engine)
Base=declarative_base()
ADMIN_EMAIL=os.getenv('ADMIN_EMAIL','contato.lucasmacedodev@gmail.com').lower()
SECRET=os.environ.get('SESSION_SECRET','')
if len(SECRET)<32: raise RuntimeError('SESSION_SECRET precisa ter ao menos 32 caracteres aleatórios')
signer=URLSafeTimedSerializer(SECRET,salt='ilan-session')
passwords=PasswordHash.recommended()

class User(Base):
    __tablename__='ilan_users'
    id=Column(String,primary_key=True)
    email=Column(String(320),unique=True,nullable=False)
    password_hash=Column(String,nullable=False)
    role=Column(String,nullable=False,default='leader')
    verified=Column(Boolean,default=False,nullable=False)
    approved=Column(Boolean,default=False,nullable=False)
    token_hash=Column(String,nullable=True)
    token_expires=Column(DateTime,nullable=True)
    created_at=Column(DateTime,default=datetime.utcnow)

Base.metadata.create_all(engine)
router=APIRouter(prefix='/api/auth')
class Credentials(BaseModel):
    email:EmailStr
    password:str=Field(min_length=12,max_length=256)
class EmailOnly(BaseModel):
    email:EmailStr
class Decision(BaseModel):
    approved:bool

def public(u):return {'id':u.id,'email':u.email,'role':u.role,'verified':u.verified,'approved':u.approved}
def send_verification(email,token):
    host=os.getenv('SMTP_HOST','');username=os.getenv('SMTP_USER','');pw=os.getenv('SMTP_PASSWORD','')
    if not all([host,username,pw,os.getenv('PUBLIC_URL')]):raise HTTPException(503,'SMTP e PUBLIC_URL precisam ser configurados para verificação real de email.')
    link=os.getenv('PUBLIC_URL').rstrip('/')+'/api/auth/verify?token='+token
    msg=EmailMessage();msg['Subject']='Confirme seu email — Gerenciador de GTs Ilan';msg['From']=os.getenv('SMTP_FROM',username);msg['To']=email
    msg.set_content('Confirme seu endereço de email (válido por 24 horas):\n'+link)
    port=int(os.getenv('SMTP_PORT','587'))
    if port==465:
        with smtplib.SMTP_SSL(host,port,context=ssl.create_default_context(),timeout=15) as server:server.login(username,pw);server.send_message(msg)
    else:
        with smtplib.SMTP(host,port,timeout=15) as server:
            server.starttls(context=ssl.create_default_context());server.login(username,pw);server.send_message(msg)

def get_current_user(request:Request):
    cookie=request.cookies.get('ilan_session')
    if not cookie:raise HTTPException(401,'Entre na sua conta.')
    try: uid=signer.loads(cookie,max_age=60*60*12)
    except (BadSignature,SignatureExpired):raise HTTPException(401,'Sessão expirada.')
    with Session() as db:
        u=db.get(User,uid)
        if not u or not u.verified or not u.approved:raise HTTPException(403,'Conta ainda não autorizada.')
        db.expunge(u);return u
require_user=get_current_user
def require_admin(user:User=Depends(require_user)):
    if user.role!='admin':raise HTTPException(403,'Apenas o administrador.')
    return user

@router.post('/register',status_code=202)
def register(payload:Credentials):
    email=str(payload.email).strip().lower()
    with Session() as db:
        if db.scalar(select(User).where(User.email==email)):raise HTTPException(409,'Email já cadastrado.')
        token=secrets.token_urlsafe(40)
        u=User(id=secrets.token_hex(16),email=email,password_hash=passwords.hash(payload.password),role='admin' if email==ADMIN_EMAIL else 'leader',verified=False,approved=email==ADMIN_EMAIL,token_hash=hashlib.sha256(token.encode()).hexdigest(),token_expires=datetime.utcnow()+timedelta(hours=24))
        # Email must send successfully before creating user
        send_verification(email,token)
        db.add(u);db.commit()
    return {'message':'Verifique o link enviado ao seu email. Líderes precisam aguardar aprovação do administrador.'}

@router.get('/verify')
def verify(token:str):
    hashed=hashlib.sha256(token.encode()).hexdigest()
    with Session() as db:
        u=db.scalar(select(User).where(User.token_hash==hashed))
        if not u or not u.token_expires or u.token_expires<datetime.utcnow():raise HTTPException(400,'Link inválido ou expirado.')
        u.verified=True;u.token_hash=None;u.token_expires=None;db.commit()
    return {'message':'Email verificado. Entre na plataforma após aprovação, se necessária.'}

@router.post('/resend')
def resend(payload:EmailOnly):
    with Session() as db:
        u=db.scalar(select(User).where(User.email==str(payload.email).lower()))
        if u and not u.verified:
            token=secrets.token_urlsafe(40);send_verification(u.email,token)
            u.token_hash=hashlib.sha256(token.encode()).hexdigest();u.token_expires=datetime.utcnow()+timedelta(hours=24);db.commit()
    return {'message':'Se houver uma conta não verificada, enviaremos novo link.'}

@router.post('/login')
def login(payload:Credentials,response:Response):
    with Session() as db:
        u=db.scalar(select(User).where(User.email==str(payload.email).lower()))
        if not u or not passwords.verify(payload.password,u.password_hash):raise HTTPException(401,'Credenciais inválidas.')
        if not u.verified:raise HTTPException(403,'Verifique seu email antes de entrar.')
        if not u.approved:raise HTTPException(403,'Aguarde aprovação do administrador.')
        response.set_cookie('ilan_session',signer.dumps(u.id),max_age=43200,httponly=True,secure=os.getenv('COOKIE_SECURE','false').lower()=='true',samesite='lax',path='/')
        return public(u)

@router.post('/logout')
def logout(response:Response):response.delete_cookie('ilan_session',path='/');return {'ok':True}
@router.get('/me')
def me(user:User=Depends(require_user)):return public(user)
@router.get('/users')
def users(admin:User=Depends(require_admin)):
    with Session() as db:return [public(u) for u in db.scalars(select(User).order_by(User.created_at.desc())).all()]
@router.patch('/users/{uid}')
def approve(uid:str,payload:Decision,admin:User=Depends(require_admin)):
    with Session() as db:
        u=db.get(User,uid)
        if not u:raise HTTPException(404,'Usuário não encontrado.')
        if u.role=='admin':raise HTTPException(403,'Não é permitido alterar a aprovação do administrador.')
        if payload.approved and not u.verified:raise HTTPException(409,'Aguarde verificação do email.')
        u.approved=payload.approved;db.commit();return public(u)
