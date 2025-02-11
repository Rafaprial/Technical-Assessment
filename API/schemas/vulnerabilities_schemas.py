from pydantic import BaseModel, Field


class VulnerabilityBase(BaseModel):
    cve: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,7}$")  # Enforces CVE format
    title: str = Field(..., max_length=30)
    criticality: int = Field(..., ge=0, le=10)
    description: str = Field(..., max_length=100)


class VulnerabilityCreate(VulnerabilityBase):
    pass  # POST


class VulnerabilityResponse(VulnerabilityBase):
    class Config:
        orm_mode = True
