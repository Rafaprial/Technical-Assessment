from fastapi import APIRouter, Request, Depends, HTTPException
from sqlalchemy.orm import Session
from database.database_setup import SessionLocal
from models.vulnerabilities import Vulnerability
from datetime import datetime
from decorators.auth import api_key_required
from utils.logger import logger

router = APIRouter()

# Function to populate the database


def populate_database(db: Session):
    vulnerabilities = [
        Vulnerability(
            cve="CVE-2024-1234",
            title="Sample Vulnerability 1",
            criticality=7,
            description="A sample vulnerability for testing.",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        ),
        Vulnerability(
            cve="CVE-2023-5678",
            title="Sample Vulnerability 2",
            criticality=4,
            description="Another example vulnerability.",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        ),
    ]
    db.add_all(vulnerabilities)
    db.commit()


# Endpoint
@router.post("/populate-db")
async def populate_db(
    request: Request,
    role: str = Depends(api_key_required)
):
    if role == "admin":
        with SessionLocal() as db:
            # Verify if already populated
            existing_vulnerabilities = db.query(Vulnerability).first()
            if existing_vulnerabilities:
                logger.error("Database already populated!")
                return {"message": "Database already populated!"}
            else:
                populate_database(db)
                logger.info("Database populated successfully!")
                return {"message": "Database populated successfully!"}
    else:
        logger.error("A non-admin user tried to populate the db")
        raise HTTPException(status_code=403, detail="Only admin can populate the db!")

