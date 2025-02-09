from fastapi import APIRouter, Request, Depends
from sqlalchemy.orm import Session
from models import Vulnerability
from datetime import datetime
from database.database_setup import SessionLocal
from decorators.auth import api_key_check
from schemas.vulnerabilities_schemas import VulnerabilityCreate

router = APIRouter()


# Function to populate the database
def populate_database(db: Session):
    vulnerabilities_data = [
        {
            "cve": "CVE-2024-1234",
            "title": "Sample Vulnerability 1",
            "criticality": 7,
            "description": "A sample vulnerability for testing."
        },
        {
            "cve": "CVE-2023-5678",
            "title": "Sample Vulnerability 2",
            "criticality": 4,
            "description": "Another example vulnerability."
        }
    ]
    # Validate the data using schema
    for vulnerability_data in vulnerabilities_data:
        validated_data = VulnerabilityCreate(**vulnerability_data)
        # Now that the data is validated
        vulnerability = Vulnerability(
            cve=validated_data.cve,
            title=validated_data.title,
            criticality=validated_data.criticality,
            description=validated_data.description,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        db.add(vulnerability)
    db.commit()


# Endpoint to trigger the population


@router.post("/populate-db")
async def populate_db(request: Request, api_key: str = Depends(api_key_check)):
    with SessionLocal() as db:
        # Verify if already populated
        existing_vulnerabilities = db.query(Vulnerability).first()
        if existing_vulnerabilities:
            return {"message": "Database already populated!"}
        else:
            populate_database(db)
            return {"message": "Database populated successfully!"}
