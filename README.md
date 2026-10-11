# DepScan --- Dependency Vulnerability Scanner

DepScan is a backend project that scans GitHub repositories for
dependencies, checks those dependencies against the [OSV vulnerability
database](https://osv.dev/), and produces a security summary. It
combines dependency parsing, vulnerability lookup, dependency-graph
analysis, risk scoring, persistent storage, caching, and a dashboard/API
layer.

## Features

-   **GitHub repository scanning** --- retrieves repository file
    information through the GitHub API.
-   **Manifest detection and dependency parsing** --- detects supported
    dependency files and extracts dependencies.
-   **Multiple package ecosystems** --- includes support for common
    manifest formats such as:
    -   Python: `requirements.txt`, `pyproject.toml`, `Pipfile`
    -   JavaScript: `package.json`
    -   Rust: `Cargo.toml`
    -   Java: `pom.xml`, `build.gradle`
    -   PHP: `composer.json`
    -   Ruby: `Gemfile`
    -   Go: `go.mod`
    -   Dart/Flutter: `pubspec.yaml`
-   **Vulnerability lookup** --- queries OSV for known vulnerabilities
    affecting detected dependencies.
-   **PostgreSQL persistence** --- stores scan results and vulnerability
    information using SQLAlchemy.
-   **Dependency graph analysis** --- represents dependencies as a graph
    and supports dependency-path and dependency-type analysis.
-   **Risk scoring** --- calculates a security score using vulnerability
    severity and dependency characteristics, including direct/transitive
    status and graph depth.
-   **Redis caching** --- caches vulnerability query results to reduce
    repeated requests.
-   **FastAPI API** --- exposes the scanner through HTTP endpoints and
    interactive API documentation.
-   **Docker Compose setup** --- runs the API, PostgreSQL, and Redis as
    services.

## Tech stack

-   **Language:** Python
-   **API:** FastAPI, Uvicorn
-   **Database:** PostgreSQL, SQLAlchemy
-   **Cache:** Redis
-   **Graph analysis:** NetworkX
-   **Package/version parsing:** `packaging`
-   **Vulnerability data:** OSV API
-   **Containerization:** Docker, Docker Compose
-   **Testing/CI:** Planned as a follow-up phase; do not assume tests or
    GitHub Actions are configured unless they are present in the
    repository.

## Architecture

``` text
GitHub repository URL
        |
        v
  FastAPI application
        |
        +--> GitHub API: inspect repository files
        |
        +--> Manifest detection and dependency parsing
        |
        +--> Dependency graph and risk analysis
        |
        +--> OSV vulnerability queries <--> Redis cache
        |
        v
    PostgreSQL
        |
        v
 Scan summary / API response / dashboard
```

When using Docker Compose, the API connects to PostgreSQL through the
service hostname `postgres` and Redis through `redis`. These names work
inside the Compose network; `localhost` inside the API container refers
to the API container itself.

## Prerequisites

-   [Docker Desktop](https://www.docker.com/products/docker-desktop/) or
    Docker Engine with the Docker Compose plugin
-   Git
-   A GitHub repository URL to scan

You do not need to install Python, PostgreSQL, or Redis locally when
running the complete stack with Docker Compose.

## Quick start with Docker Compose

### 1. Clone the repository

``` bash
git clone https://github.com/Yuvraj-Mottan/Dependency_scan.git
cd Dependency_scan
```

If your local directory or repository name differs, enter the directory
containing `compose.yaml`.

### 2. Create your environment file

Copy the example configuration:

**Windows PowerShell**

``` powershell
Copy-Item .env.example .env
```

**Linux/macOS**

``` bash
cp .env.example .env
```

If the repository does not yet include `.env.example`, create `.env`
using the variable names shown below.

Example configuration:

``` env
DB_USER=depscan
DB_PASSWORD=change_me
DB_NAME=project2
DATABASE_URL=postgresql://depscan:change_me@postgres:5432/project2
```

Replace `change_me` with a password of your choice. The values in
`DATABASE_URL` must match `DB_USER`, `DB_PASSWORD`, and `DB_NAME`.
Special characters in a database URL password must be URL-encoded; for
example, `@` becomes `%40`.

**Security:** Never commit your real `.env` file or credentials to
GitHub. Commit `.env.example` with placeholders instead.

### 3. Build and start the services

``` bash
docker compose up --build
```

Docker Compose starts the FastAPI application, PostgreSQL, and Redis.

### 4. Open the API

-   Interactive Swagger documentation: <http://localhost:8000/docs>
-   OpenAPI schema: <http://localhost:8000/openapi.json>

Use the interactive documentation to inspect the endpoints available in
the current version and submit a scan.

### 5. Stop the services

Press `Ctrl+C` in the terminal, or run this in another terminal:

``` bash
docker compose down
```

The named PostgreSQL volume preserves database data when the containers
are stopped and removed.

> **Warning:** `docker compose down -v` also removes Compose-managed
> volumes and can delete the stored PostgreSQL data. Use it only when
> you intentionally want to reset the database.

## Environment variables

  ---------------------------------------------------------------------------------------------------------
  Variable                Purpose                 Example
  ----------------------- ----------------------- ---------------------------------------------------------
  `DB_USER`               PostgreSQL username     `depscan`
                          used by the database    
                          service                 

  `DB_PASSWORD`           PostgreSQL password     `change_me`

  `DB_NAME`               PostgreSQL database     `project2`
                          name                    

  `DATABASE_URL`          Connection URL used by  `postgresql://depscan:change_me@postgres:5432/project2`
                          the API                 

  `REDIS_HOST`            Redis hostname used by  `redis`
                          the API in Compose      

  `REDIS_PORT`            Redis port used by the  `6379`
                          API in Compose          
  ---------------------------------------------------------------------------------------------------------

`REDIS_HOST` and `REDIS_PORT` are configured by the Compose file for the
API service. If you run the API outside Docker, you may need to set them
to match your local Redis setup.

## Useful Docker commands

Check service status:

``` bash
docker compose ps
```

View logs from all services:

``` bash
docker compose logs -f
```

View only API logs:

``` bash
docker compose logs -f api
```

Rebuild and restart after changing application code or dependencies:

``` bash
docker compose up --build
```

Run the services in the background:

``` bash
docker compose up --build -d
```

Stop background services:

``` bash
docker compose down
```

## Project structure

The exact structure may evolve, but the project is organized around the
FastAPI application and its supporting modules:

``` text
Project2/
├── app/
│   ├── main.py              # FastAPI application and API routes
│   ├── database.py          # Database/session utilities
│   ├── models.py            # SQLAlchemy models
│   ├── osv_client.py        # OSV vulnerability queries and caching
│   ├── dependency_graph.py  # Dependency graph analysis
│   └── risk.py              # Security risk scoring
├── Dockerfile
├── compose.yaml
├── .dockerignore
├── .env.example             # Safe template; add this if not present
├── .gitignore
├── requirements.txt
└── README.md
```

## Current implementation status

Implemented so far:

-   GitHub repository file discovery
-   Dependency manifest detection and parsing
-   PostgreSQL integration through SQLAlchemy
-   OSV vulnerability querying
-   Vulnerability persistence
-   Dependency graph analysis
-   Security risk scoring
-   Scan-summary API endpoint(s)
-   Redis caching for vulnerability queries
-   Docker Compose setup for FastAPI, PostgreSQL, and Redis
-   Environment-based configuration for running the stack

Automated test coverage and GitHub Actions CI are a planned follow-up
unless they have since been added to the repository.

## Troubleshooting

### API cannot connect to PostgreSQL

-   Confirm the PostgreSQL service is healthy with `docker compose ps`.
-   Inside Compose, the database hostname should be `postgres`, not
    `localhost`.
-   Check that `DATABASE_URL` uses the same credentials and database
    name as `DB_USER`, `DB_PASSWORD`, and `DB_NAME`.
-   URL-encode special characters in the password inside `DATABASE_URL`.

### API cannot connect to Redis

-   Inside Compose, set the Redis hostname to `redis` and port to
    `6379`.
-   Inspect logs with:

``` bash
docker compose logs -f api redis
```

### Port 8000 is already in use

Stop the process using port 8000, or change the host-side port mapping
in `compose.yaml`. For example, `"8001:8000"` makes the API available at
`http://localhost:8001` while the container continues to listen on port
8000.

