from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from services.crud import create_vulnerability, get_vulnerability_by_cve, get_vulnerabilities, soft_delete_vulnerability
from schemas.vulnerabilities_schemas import VulnerabilityCreate, VulnerabilityResponse
from decorators.auth import api_key_required
from database.database_setup import SessionLocal
from decorators.limiter import limiter
from fastapi import Request
from utils.logger import logger

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
@limiter.limit("10/minute")
async def create_vulnerability_endpoint(request:Request, vulnerability: VulnerabilityCreate, db: Session = Depends(get_db), role: str = Depends(api_key_required)):
    if role == "admin":
        return create_vulnerability(db=db, vulnerability=vulnerability)
    else:
        logger.error(f"A non-admin user tried to create a vulnerability")
        raise HTTPException(status_code=403, detail="Only admin can create vulnerabilities!")

# Get a vulnerability by CVE
@router.get("/vulnerability/{cve}", response_model=VulnerabilityResponse)
@limiter.limit("20/minute")
def get_vulnerability(request:Request, cve: str, db: Session = Depends(get_db), role: str = Depends(api_key_required)):
    if role == "user" or role == "admin":
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
    else:
        logger.error(f"A non-verified user tried to get a vulnerability by CVE")
        raise HTTPException(status_code=403, detail="Only verified users can get a vulnerability by CVE!")

# Get all vulnerabilities and filters
@router.get("/vulnerability", response_model=list[VulnerabilityResponse])
@limiter.limit("20/minute")
def get_vulnerabilities_endpoint(
    request: Request,
    title: str = None,
    min_criticality: int = None,
    max_criticality: int = None,
    skip: int = 0,
    limit: int = 10,
    db: Session = Depends(get_db),
    role: str = Depends(api_key_required)
):
    if role == "user" or role == "admin":
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
                logger.error(f"No vulnerabilities found")
                raise HTTPException(status_code=404, detail="No vulnerabilities found")
            
            return vulnerabilities
        except Exception as e:
            logger.error(f"Error getting vulnerabilities: {str(e)}")
            raise HTTPException(status_code=500, detail=str(e))
    else:
        logger.error(f"A non-verified user tried to get all vulnerabilities")
        raise HTTPException(status_code=403, detail="Only verified users can get all vulnerabilities!")

# Delete a vulnerability by CVE
@router.delete("/vulnerability/{cve}", response_model=VulnerabilityResponse)
@limiter.limit("10/minute")
def delete_vulnerability_endpoint(request: Request, cve: str, db: Session = Depends(get_db), role: str = Depends(api_key_required)):
    if role == "admin":
        db_vulnerability = soft_delete_vulnerability(db=db, cve=cve)
        if db_vulnerability is None:
            logger.error(f"Vulnerability with CVE {cve} not found")
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        return db_vulnerability
    else:
        logger.error(f"A non-admin user tried to delete a vulnerability")
        raise HTTPException(status_code=403, detail="Only admin can delete vulnerabilities!") 

