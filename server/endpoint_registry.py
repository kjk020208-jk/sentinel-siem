from datetime import datetime
from typing import Optional
import os
import secrets

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.orm import Session

from server.database import Base, get_db
from server.models import MonitoredUser

router = APIRouter()

ONLINE_SECONDS = int(os.getenv("SENTINEL_ENDPOINT_ONLINE_SECONDS", "45"))
AGENT_TOKEN = os.getenv("SENTINEL_AGENT_TOKEN", "").strip()


class EndpointRegistry(Base):
    __tablename__ = "endpoint_registry"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String, unique=True, index=True, nullable=False)
    hostname = Column(String, nullable=False)
    windows_user = Column(String, nullable=True)
    endpoint_ip = Column(String, nullable=True)
    endpoint_network = Column(String, nullable=True)
    linked_user = Column(String, nullable=True, index=True)
    agent_version = Column(String, nullable=True)
    status = Column(String, nullable=False, default="PENDING")
    first_seen_at = Column(DateTime, nullable=False, default=datetime.now)
    last_seen_at = Column(DateTime, nullable=False, default=datetime.now)


class AgentRegister(BaseModel):
    agent_id: str
    hostname: str
    windows_user: Optional[str] = None
    endpoint_ip: Optional[str] = None
    endpoint_network: Optional[str] = None
    sentinel_user: Optional[str] = None
    agent_version: Optional[str] = None


class AgentHeartbeat(BaseModel):
    agent_id: str
    hostname: Optional[str] = None
    windows_user: Optional[str] = None
    endpoint_ip: Optional[str] = None
    endpoint_network: Optional[str] = None
    sentinel_user: Optional[str] = None
    agent_version: Optional[str] = None


class EndpointLink(BaseModel):
    username: str


def _check_agent_token(token: Optional[str]):
    if not AGENT_TOKEN:
        return
    if not token or not secrets.compare_digest(token, AGENT_TOKEN):
        raise HTTPException(status_code=401, detail="유효하지 않은 SENTINEL Agent Token입니다.")


def _serialize(row):
    now = datetime.now()
    age = (now - row.last_seen_at).total_seconds() if row.last_seen_at else 999999

    if not row.linked_user:
        effective_status = "PENDING"
    elif age <= ONLINE_SECONDS:
        effective_status = "ONLINE"
    else:
        effective_status = "OFFLINE"

    return {
        "id": row.id,
        "agent_id": row.agent_id,
        "hostname": row.hostname,
        "windows_user": row.windows_user,
        "endpoint_ip": row.endpoint_ip,
        "endpoint_network": row.endpoint_network,
        "linked_user": row.linked_user,
        "agent_version": row.agent_version,
        "status": effective_status,
        "first_seen_at": row.first_seen_at.isoformat() if row.first_seen_at else None,
        "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
        "last_seen_seconds": max(0, int(age)),
    }


def _upsert(db: Session, body):
    now = datetime.now()
    row = db.query(EndpointRegistry).filter(
        EndpointRegistry.agent_id == body.agent_id
    ).first()

    if not row:
        row = EndpointRegistry(
            agent_id=body.agent_id,
            hostname=body.hostname or body.agent_id,
            windows_user=body.windows_user,
            endpoint_ip=body.endpoint_ip,
            endpoint_network=body.endpoint_network,
            agent_version=body.agent_version,
            first_seen_at=now,
            last_seen_at=now,
        )
        db.add(row)

    if body.hostname:
        row.hostname = body.hostname
    if body.windows_user:
        row.windows_user = body.windows_user
    if body.endpoint_ip:
        row.endpoint_ip = body.endpoint_ip
    if body.endpoint_network:
        row.endpoint_network = body.endpoint_network
    if body.agent_version:
        row.agent_version = body.agent_version

    candidate = (body.sentinel_user or "").strip()

    if candidate:
        monitored = db.query(MonitoredUser).filter(
            MonitoredUser.username == candidate
        ).first()

        if monitored:
            row.linked_user = candidate
            row.status = "ONLINE"
        elif not row.linked_user:
            row.status = "PENDING"

    row.last_seen_at = now
    db.commit()
    db.refresh(row)
    return row


@router.post("/agent/register")
def register_agent(
    body: AgentRegister,
    db: Session = Depends(get_db),
    x_agent_token: Optional[str] = Header(default=None, alias="X-Agent-Token"),
):
    _check_agent_token(x_agent_token)
    row = _upsert(db, body)
    return {"ok": True, "endpoint": _serialize(row)}


@router.post("/agent/heartbeat")
def heartbeat_agent(
    body: AgentHeartbeat,
    db: Session = Depends(get_db),
    x_agent_token: Optional[str] = Header(default=None, alias="X-Agent-Token"),
):
    _check_agent_token(x_agent_token)
    row = _upsert(db, body)
    return {"ok": True, "endpoint": _serialize(row)}


@router.get("/endpoints")
def list_endpoints(db: Session = Depends(get_db)):
    rows = db.query(EndpointRegistry).order_by(
        EndpointRegistry.last_seen_at.desc()
    ).all()

    return {
        "items": [_serialize(row) for row in rows],
        "total": len(rows),
    }


@router.post("/endpoints/{agent_id}/link")
def link_endpoint(
    agent_id: str,
    body: EndpointLink,
    db: Session = Depends(get_db),
):
    row = db.query(EndpointRegistry).filter(
        EndpointRegistry.agent_id == agent_id
    ).first()

    if not row:
        raise HTTPException(status_code=404, detail="Endpoint를 찾을 수 없습니다.")

    monitored = db.query(MonitoredUser).filter(
        MonitoredUser.username == body.username
    ).first()

    if not monitored:
        raise HTTPException(status_code=404, detail="등록된 모니터링 사용자가 아닙니다.")

    row.linked_user = body.username
    row.status = "ONLINE"

    db.commit()
    db.refresh(row)

    return {"ok": True, "endpoint": _serialize(row)}
