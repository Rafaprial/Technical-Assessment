from pydantic import BaseModel, Field
from typing import List


class VulnerabilityBase(BaseModel):
    cve: str = Field(...)
    title: str = Field(...)
    criticality: int = Field(...)
    description: str = Field(...)


class VulnerabilityCreate(VulnerabilityBase):
    pass  # POST


class VulnerabilityResponse(VulnerabilityBase):
    class Config:
        orm_mode = True


class VulnerabilitySummaryOfCreationResponse(BaseModel):
    created_count: int
    restored_count: int
    skipped_cves: int
    invalid_cves: int