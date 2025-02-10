from sqlalchemy.orm import Session
from fastapi import HTTPException
from models.vulnerabilities import Vulnerability
from schemas.vulnerabilities_schemas import VulnerabilityCreate
from datetime import datetime

MAX_LIMIT = 100

# Create a new vulnerability
def create_vulnerability(db: Session, vulnerability: VulnerabilityCreate):
    db_vulnerability = db.query(Vulnerability).filter(Vulnerability.cve == vulnerability.cve).first()
    
    if db_vulnerability:
        if db_vulnerability.is_deleted:  # If the CVE is soft deleted, "restore" it
            db_vulnerability.is_deleted = False
            db_vulnerability.deleted_at = None  # Remove the deleted timestamp
            db_vulnerability.title = vulnerability.title
            db_vulnerability.criticality = vulnerability.criticality
            db_vulnerability.description = vulnerability.description
            db_vulnerability.updated_at = datetime.utcnow()
            db.commit()
            db.refresh(db_vulnerability)
            return db_vulnerability
        else:
            raise HTTPException(status_code=400, detail="Vulnerability with this CVE already exists")
    
    # If the CVE doesn't exist, create a new vulnerability
    new_vulnerability = Vulnerability(
        cve=vulnerability.cve,
        title=vulnerability.title,
        criticality=vulnerability.criticality,
        description=vulnerability.description,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    db.add(new_vulnerability)
    db.commit()
    db.refresh(new_vulnerability)
    return new_vulnerability

# Get a vulnerability by CVE
def get_vulnerability_by_cve(db: Session, cve: str):
    return db.query(Vulnerability).filter(Vulnerability.cve == cve, Vulnerability.is_deleted == False).first()

# Get all vulnerabilities with optional filtering by title and criticality
def get_vulnerabilities(db: Session, title: str = None, min_criticality: int = None, max_criticality: int = None, skip: int = 0, limit: int = 10):
    if limit > MAX_LIMIT:
        raise HTTPException(
            status_code=400,
            detail=f"Limit cannot exceed {MAX_LIMIT}"
        )
        #Change HTTPException to personal exception
    query = db.query(Vulnerability).filter(Vulnerability.is_deleted == False)
    
    if title:
        query = query.filter(Vulnerability.title.ilike(f"%{title}%"))
    if min_criticality is not None:
        query = query.filter(Vulnerability.criticality >= min_criticality)
    if max_criticality is not None:
        query = query.filter(Vulnerability.criticality <= max_criticality)
    
    return query.offset(skip).limit(limit).all()


# Soft delete
def soft_delete_vulnerability(db: Session, cve: str):
    db_vulnerability = db.query(Vulnerability).filter(Vulnerability.cve == cve).first()
    
    if db_vulnerability:
        db_vulnerability.is_deleted = True
        db_vulnerability.deleted_at = datetime.utcnow()
        db.commit()
        db.refresh(db_vulnerability)
        return db_vulnerability
    return None  # Return None if the vulnerability is not found