# Technical-Assessment
Technical assesssment for Swiss Re

# FastAPI Vulnerability Management API

This is a FastAPI-based API designed to manage vulnerabilities through CRUD operations. It supports handling large datasets, integrates security mechanisms like API key authentication, and protects against common attacks such as SQL injection and DDoS.

## Features
- **CRUD Operations** for managing vulnerabilities.
- **API Key Authentication** for secure access.
- **Pagination & Caching** to handle large datasets efficiently.
- **SQL Injection Protection** using SQLAlchemy.
- **Rate Limiting** to protect against DDoS attacks.
- **Connection Pooling** for efficient database connections.

## Endpoints

# /GET
- `/vulnerability/{cve}`
    - Returns the vulnerability by CVE.
    - Potential status codes: `400, 404, 500`.
- `/vulnerability`
    - Retrieves all vulnerabilities if any filter is applied.
    - It must allow filtering by the following parameters:
        - `Title`: contains.
        - `Max/Min Criticity`: values in between.
    - Potential status codes: `400, 404, 500`.

# /POST
- `/vulnerability`
    - Creates a new vulnerability object.
    - The values of the new object must be included in the body.
    - Potential status codes: `400, 404, 500`.

# /DELETE
- `/vulnerability/{cve}`
    - Removes the specific vulnerability.
    - Returns the removed vulnerability.
    - Potential status codes: `400, 404, 500`.

# USAGE