from fastapi import APIRouter, Depends
from sqlmodel import Session

from database.database import get_session
from models.network_flow import NetworkFlow


router = APIRouter(
    prefix="/network-flows",
    tags=["Network Flows"]
)


@router.post("/")
def create_network_flow(
    flow: NetworkFlow,
    session: Session = Depends(get_session)
):
    session.add(flow)
    session.commit()
    session.refresh(flow)

    return flow


@router.get("/")
def get_network_flows(
    session: Session = Depends(get_session)
):
    return session.query(NetworkFlow).all()