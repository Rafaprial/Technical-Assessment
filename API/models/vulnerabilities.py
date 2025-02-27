from sqlalchemy import Column, Integer, String, DateTime, Boolean, CheckConstraint
from database.database_setup import Base
from datetime import datetime


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    cve = Column(String,  nullable=False, primary_key=True, index=True, unique=True)  # Primary key
    title = Column(String(30),  nullable=False)  # Column with a maximum of 30 characters
    criticality = Column(Integer,  nullable=False)  # Column with an integer
    description = Column(String(100), nullable=False)  # Column with a maximum of 100 characters
    created_at = Column("InsertTimeStamp", DateTime, nullable=False, default=datetime.utcnow)  # Column with a timestamp
    updated_at = Column("UpdateTimeStamp", DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    # Column with a timestamp that updates when the row is updated
    is_deleted = Column(Boolean, default=False)  # New column to track soft deletes <--- Best to avoid losing data
    deleted_at = Column("DeletedTimeStamp", DateTime)  # Timestamp for when it was deleted

    __table_args__ = (
        CheckConstraint("cve LIKE 'CVE-%'", name="check_cve_format"),
    )
