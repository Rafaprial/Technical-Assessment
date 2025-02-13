from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from fastapi import HTTPException
from models.vulnerabilities import Vulnerability
from schemas.vulnerabilities_schemas import VulnerabilityCreate, VulnerabilitySummaryOfCreationResponse
from datetime import datetime
import re

from utils.logger import logger
from exceptions.exceptions_handlers import VulnerabilityNotFoundException

MAX_LIMIT = 100

from sqlalchemy.exc import IntegrityError
from fastapi import HTTPException
import re
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

def create_vulnerability(db: Session, vulnerabilities: list[VulnerabilityCreate]):
    valid_vulnerabilities = []
    invalid_cves = set()
    
    # Validate CVE format
    cve_pattern = re.compile(r"^CVE-\d{4}-\d{4,}$")
    for v in vulnerabilities:
        if not cve_pattern.match(v.cve):
            invalid_cves.add(v.cve)
        else:
            valid_vulnerabilities.append(v)

    # Process body in smaller parts
    cve_list = [v.cve for v in valid_vulnerabilities]
    existing_vulnerabilities = set()
    batch_size = 5000

    for i in range(0, len(cve_list), batch_size):
        batch = cve_list[i:i + batch_size]
        existing_vulnerabilities.update(
            v.cve for v in db.query(Vulnerability.cve)
            .filter(Vulnerability.cve.in_(batch))
            .yield_per(1000)  # Yield to not break the memory
        )

    # Bulk insert
    new_vulnerabilities = [
        {
            "cve": v.cve,
            "title": v.title,
            "criticality": v.criticality,
            "description": v.description,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "is_deleted": False
        }
        for v in valid_vulnerabilities if v.cve not in existing_vulnerabilities
    ]

    
    try:
        if new_vulnerabilities:
            insert_batch_size = 10000  # Insert every 10k rows
            for i in range(0, len(new_vulnerabilities), insert_batch_size):
                db.bulk_insert_mappings(Vulnerability, new_vulnerabilities[i:i + insert_batch_size])
                db.commit()
    except IntegrityError as e:
        db.rollback()
        logger.error(f"Database error occurred: {str(e)}")
        raise HTTPException(status_code=500, detail="A database error occurred.")
    except Exception as e:
        db.rollback()
        logger.error(f"Unexpected error: {str(e)}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred.")

    logger.info(f"Created {len(new_vulnerabilities)} new vulnerabilities, "
                f"skipped {len(existing_vulnerabilities)}, "
                f"invalid {len(invalid_cves)} CVEs")

    return VulnerabilitySummaryOfCreationResponse(
        created_count=len(new_vulnerabilities),
        restored_count=0,
        skipped_cves=len(existing_vulnerabilities),
        invalid_cves=list(invalid_cves)
    )





# Get a vulnerability by CVE
def get_vulnerability_by_cve(db: Session, cve: str):
    logger.info(f"Getting vulnerability with CVE {cve}")
    return db.query(Vulnerability).filter(Vulnerability.cve == cve, Vulnerability.is_deleted == False).first()

# Get all vulnerabilities with optional filtering by title and criticality
def get_vulnerabilities(db: Session, title: str = None, min_criticality: int = None, max_criticality: int = None, skip: int = 0, limit: int = 10):
    if limit > MAX_LIMIT:
        logger.error(f"Limit on request exceeded: {limit}")
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
    logger.info(f"Getting vulnerabilities with title {title}, min_criticality {min_criticality}, max_criticality {max_criticality}")
    return query.offset(skip).limit(limit).all()


# Soft delete
def soft_delete_vulnerability(db: Session, cve: str):
    db_vulnerability = db.query(Vulnerability).filter(Vulnerability.cve == cve, Vulnerability.is_deleted==False).first()
    
    if db_vulnerability:
        db_vulnerability.is_deleted = True
        db_vulnerability.deleted_at = datetime.utcnow()
        db.commit()
        db.refresh(db_vulnerability)
        logger.info(f"Vulnerability with CVE {cve} soft deleted")
        return db_vulnerability
    else:
        logger.error(f"Vulnerability with CVE {cve} not found. Could not be Deleted")
        raise VulnerabilityNotFoundException(status_code=404, detail=f"Vulnerability with CVE {cve} not found. Could not be Deleted")