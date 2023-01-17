import secrets
import time

import bcrypt
import jwt
from fastapi import Depends, FastAPI, Form, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError

JWT_KEY = "hs256-secret-key"

app = FastAPI(docs_url="/")


class User(BaseModel):
    id: str
    username: str
    hashed_password: bytes


class UserRepository:
    def __init__(self) -> None:
        self._users = [
            User(
                id="d363b542-0938-459e-8b6d-a9d261a99948",
                username="johndoe",
                hashed_password=b"$2b$12$5NYvsxP5hmH9DO8sRI4p/ugpOmIQW7kiNTH5ZygKYM1wTurKFYlfm",
            ),
        ]

    def get_user_by_id(self, id: str) -> User | None:
        for user in self._users:
            if user.id == id:
                return user
        return None

    def get_user_by_username(self, username: str) -> User | None:
        for user in self._users:
            if user.username == username:
                return user
        return None


class OAuth2Error(Exception):
    def __init__(self, status_code: int, error: str, error_description: str) -> None:
        self.status_code = status_code
        self.error = error
        self.error_description = error_description


INVALID_USERNAME_OR_PASSWORD = OAuth2Error(
    status_code=status.HTTP_400_BAD_REQUEST,
    error="invalid_request",
    error_description="invalid username or password",
)
INVALID_REFRESH_TOKEN = OAuth2Error(
    status_code=status.HTTP_400_BAD_REQUEST,
    error="invalid_request",
    error_description="invalid refresh_token",
)
INVALID_GRANT_TYPE = OAuth2Error(
    status_code=status.HTTP_400_BAD_REQUEST,
    error="unsupported_grant_type",
    error_description="only password and refresh_token grant types supported",
)


def _hours_from_now(hours: float) -> int:
    return int(time.time() + 3600 * hours)


def _days_from_now(days: float) -> int:
    return _hours_from_now(days * 24)


class BaseToken(BaseModel):
    sub: str

    def encode(self, key: str) -> str:
        return jwt.encode(self.dict(), key=key, algorithm="HS256")


class AccessToken(BaseToken):
    exp: int = Field(default_factory=lambda: _hours_from_now(10))
    token_type = "access"


class IdToken(BaseToken):
    exp: int = Field(default_factory=lambda: _hours_from_now(10))
    token_type = "id"


class RefreshToken(BaseToken):
    exp: int = Field(default_factory=lambda: _days_from_now(30))
    jti: str = Field(default_factory=lambda: secrets.token_hex(16))
    token_type = "refresh"


class LoginResponse(BaseModel):
    access_token: str
    id_token: str
    refresh_token: str
    token_type: str = "Bearer"


def is_valid_password(password: str, hashed_password: bytes) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed_password)


async def login_username_password(
    user_repo: UserRepository, username: str, password: str
) -> User:
    user = user_repo.get_user_by_username(username)
    if user is None:
        raise INVALID_USERNAME_OR_PASSWORD

    if is_valid_password(password, user.hashed_password):
        return user

    raise INVALID_USERNAME_OR_PASSWORD


async def login_refresh_token(user_repo: UserRepository, refresh_token: str) -> User:
    try:
        claims = RefreshToken(
            **jwt.decode(refresh_token, JWT_KEY, algorithms=["HS256"])
        )
    except (jwt.InvalidTokenError, ValidationError):
        raise INVALID_REFRESH_TOKEN

    user_id = claims.sub
    user = user_repo.get_user_by_id(user_id)
    if user is None:
        raise INVALID_REFRESH_TOKEN
    return user


async def get_request_user(
    user_repo: UserRepository = Depends(), authorization: str | None = Header(None)
) -> User:
    if authorization is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED)

    try:
        access_token = authorization.strip()[7:]
    except IndexError:
        raise HTTPException(status.HTTP_403_FORBIDDEN)

    try:
        claims = AccessToken(**jwt.decode(access_token, JWT_KEY, algorithms=["HS256"]))
    except (jwt.InvalidTokenError, ValidationError):
        raise HTTPException(status.HTTP_403_FORBIDDEN)

    user_id = claims.sub
    user = user_repo.get_user_by_id(user_id)
    if user is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN)
    return user


@app.exception_handler(OAuth2Error)
async def oauth2_exception_boundary(_: Request, exc: OAuth2Error) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.error, "error_description": exc.error_description},
    )


@app.post("/oauth/token")
async def login(
    user_repo: UserRepository = Depends(),
    grant_type: str | None = Form(None),
    username: str | None = Form(None),
    password: str | None = Form(None),
    refresh_token: str | None = Form(None),
) -> LoginResponse:
    if grant_type == "password":
        if username is None or password is None:
            raise INVALID_USERNAME_OR_PASSWORD
        user = await login_username_password(user_repo, username, password)

    elif grant_type == "refresh_token":
        if refresh_token is None:
            raise INVALID_REFRESH_TOKEN
        user = await login_refresh_token(user_repo, refresh_token)

    else:
        raise INVALID_GRANT_TYPE

    return LoginResponse(
        access_token=AccessToken(sub=user.id).encode(JWT_KEY),
        id_token=IdToken(sub=user.id).encode(JWT_KEY),
        refresh_token=RefreshToken(sub=user.id).encode(JWT_KEY),
    )


@app.get("/public")
async def public() -> dict[str, str]:
    return {"message": "public 🔥"}


@app.get("/private")
async def private(user: User = Depends(get_request_user)) -> dict[str, str]:
    return {"message": "private 🚀", "id": user.id}
