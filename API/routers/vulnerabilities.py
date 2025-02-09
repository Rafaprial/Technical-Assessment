from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from services.crud import create_vulnerability, get_vulnerability_by_cve, get_vulnerabilities, soft_delete_vulnerability
from schemas.vulnerabilities_schemas import VulnerabilityCreate, VulnerabilityResponse
from database.database_setup import SessionLocal

router = APIRouter()

# Dependency to get the DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Create a new vulnerability
@router.post("/vulnerability", response_model=VulnerabilityResponse)
def create_vulnerability_endpoint(vulnerability: VulnerabilityCreate, db: Session = Depends(get_db)):
    return create_vulnerability(db=db, vulnerability=vulnerability)

# Get a vulnerability by CVE
@router.get("/vulnerability/{cve}", response_model=VulnerabilityResponse)
def get_vulnerability(cve: str, db: Session = Depends(get_db)):
    try:
        if not cve:
            raise HTTPException(status_code=400, detail="CVE must be provided")
        db_vulnerability = get_vulnerability_by_cve(db=db, cve=cve)
        if db_vulnerability is None:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        return db_vulnerability
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Get all vulnerabilities and filters
@router.get("/vulnerability", response_model=list[VulnerabilityResponse])
def get_vulnerabilities_endpoint(
    title: str = None,
    min_criticality: int = None,
    max_criticality: int = None,
    skip: int = 0,
    limit: int = 10,
    db: Session = Depends(get_db)
):
    try:
        # Validate criticality range
        if min_criticality is not None and max_criticality is not None and min_criticality > max_criticality:
            raise HTTPException(status_code=400, detail="min_criticality cannot be greater than max_criticality")
        
        vulnerabilities = get_vulnerabilities(
            db=db,
            title=title,
            min_criticality=min_criticality,
            max_criticality=max_criticality,
            skip=skip,
            limit=limit
        )
        
        if vulnerabilities is None or len(vulnerabilities) == 0:
            raise HTTPException(status_code=404, detail="No vulnerabilities found")
        
        return vulnerabilities
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Delete a vulnerability by CVE
@router.delete("/vulnerability/{cve}", response_model=VulnerabilityResponse)
def delete_vulnerability_endpoint(cve: str, db: Session = Depends(get_db)):
    db_vulnerability = soft_delete_vulnerability(db=db, cve=cve)
    if db_vulnerability is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return db_vulnerability

