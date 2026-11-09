from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
import os


# -------------------------------------------------
# SENTINEL Database Configuration
#
# Local:
#   SENTINEL_DB_PATH 미설정
#   -> 프로젝트/data/security.db
#
# Railway:
#   SENTINEL_DB_PATH=/data/security.db
#   -> Railway Volume 사용
# -------------------------------------------------

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

DEFAULT_DB_PATH = os.path.join(
    BASE_DIR,
    "data",
    "security.db"
)

DB_PATH = os.getenv(
    "SENTINEL_DB_PATH",
    DEFAULT_DB_PATH
)

# DB 디렉터리가 없으면 자동 생성
DB_DIRECTORY = os.path.dirname(DB_PATH)

if DB_DIRECTORY:
    os.makedirs(
        DB_DIRECTORY,
        exist_ok=True
    )

DATABASE_URL = f"sqlite:///{DB_PATH}"

print(
    f"[SENTINEL DB] SQLite path: {DB_PATH}"
)

engine = create_engine(
    DATABASE_URL,
    connect_args={
        "check_same_thread": False
    }
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


def get_db():
    db = SessionLocal()

    try:
        yield db

    finally:
        db.close()
