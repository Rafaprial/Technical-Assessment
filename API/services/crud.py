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


def create_vulnerability(db: Session, vulnerabilities: list[VulnerabilityCreate]):
    """This method has a potential problem as more vulnerabilities are added
    to the database it will take longer to check if the CVE is already in
    the database, this can be easily fixed by implementing S3 and querying through athena"""

    """Also to take in mind as better the computer and DB better the performance by proccesing more data at the same time"""

    """Multiple threads will also help to improve the performance of the system"""
    
    valid_vulnerabilities = []
    invalid_cves = set()
    unique_cves = set()
        
    cve_pattern = re.compile(r"^CVE-\d{4}-\d{4,}$")
    for v in vulnerabilities:
        if not cve_pattern.match(v.cve):
            invalid_cves.add(v.cve)
        elif v.cve not in unique_cves \
            and v.criticality is not None and 0 <= v.criticality <= 10 \
            and v.title and len(v.title) <= 30 \
            and v.description and len(v.description) <= 100:
            
            valid_vulnerabilities.append(v)
            unique_cves.add(v.cve)  # Track unique CVEs

    logger.info(f"Validated {len(valid_vulnerabilities)} vulnerabilities")

    # Process in smaller batches
    cve_list = [v.cve for v in valid_vulnerabilities]
    existing_vulnerabilities_map = {}
    batch_size = 5000

    for i in range(0, len(cve_list), batch_size):
        batch = cve_list[i:i + batch_size]
        existing_records = db.query(Vulnerability.cve, Vulnerability.is_deleted) \
            .filter(Vulnerability.cve.in_(batch)) \
            .yield_per(1000)  # Yield to prevent memory overload

        for cve, is_deleted in existing_records:
            existing_vulnerabilities_map[cve] = is_deleted

    # Lists for bulk insert and restore
    new_vulnerabilities = []
    restored_vulnerabilities = []

    for v in valid_vulnerabilities:
        if v.cve in existing_vulnerabilities_map:
            if existing_vulnerabilities_map[v.cve]:  # If is_deleted=True, restore it
                restored_vulnerabilities.append({
                    "cve": v.cve,
                    "title": v.title,
                    "criticality": v.criticality,
                    "description": v.description,
                    "updated_at": datetime.utcnow(),
                    "is_deleted": False  # Restore it
                })
        else:  # New record, add for insertion
            new_vulnerabilities.append({
                "cve": v.cve,
                "title": v.title,
                "criticality": v.criticality,
                "description": v.description,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
                "is_deleted": False
            })

    # Bulk insert and update operations
    try:
        if new_vulnerabilities:
            insert_batch_size = 10000
            for i in range(0, len(new_vulnerabilities), insert_batch_size):
                db.bulk_insert_mappings(Vulnerability, new_vulnerabilities[i:i + insert_batch_size])
        
        if restored_vulnerabilities:
            db.bulk_update_mappings(Vulnerability, restored_vulnerabilities)

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
                f"restored {len(restored_vulnerabilities)}, "
                f"skipped {len(existing_vulnerabilities_map) - len(restored_vulnerabilities)}, "
                f"invalid {len(invalid_cves)} CVEs")

    return VulnerabilitySummaryOfCreationResponse(
        created_count=len(new_vulnerabilities),
        restored_count=len(restored_vulnerabilities),
        skipped_cves=len(existing_vulnerabilities_map) - len(restored_vulnerabilities),
        invalid_cves=len(invalid_cves)
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