from fastapi import FastAPI, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from pydantic import BaseModel
from urllib.parse import urlparse
from app.database import insertData, SessionLocal
from app.dependency_graph import analyze_dependency
from app.dependency_graph import create_dependency_graph
from app.osv_client import query_vulnerability, query_dependency_range
from app.risk import (
    enrich_vulnerabilities,
    get_security_score,
    get_security_level
)
from sqlalchemy.orm import Session
import requests
import base64
from app import models


app = FastAPI()
app.mount(
    "/static",
    StaticFiles(directory="static"),
    name="static"
)

class RepositoryRequest(BaseModel):
    url: str

@app.get("/dashboard")
def dashboard():
    return FileResponse("static/index.html")


@app.get("/dashboard/{id}")
def dashboard_scan(id: int):
    return FileResponse("static/index.html")


@app.get("/")
def root():
    return {"message": "DepScan API is running"}


@app.get("/health")
def health():
    return {"status": "healthy"}


MANIFEST_FILES = {
    "requirements.txt": "PyPI",
    "pyproject.toml": "PyPI",
    "Pipfile": "PyPI",
    "package.json": "npm",
    "Cargo.toml": "crates.io",
    "pom.xml": "Maven",
    "build.gradle": "Maven",
    "composer.json": "Packagist",
    "Gemfile": "RubyGems",
    "go.mod": "Go",
    "pubspec.yaml": "Pub"
}


def parsing(st):

    st = st.strip()

    if len(st) == 0 or st[0] == '#':
        return None

    # Remove inline comments
    st = st.split("#")[0].strip()

    deli = ['==', '>=', '<=', '~=', '!=', '>', '<']

    dep_dict = {
        "name": None,
        "operator": None,
        "version": None
    }

    for d in deli:

        if d in st:

            parts = st.split(d, 1)

            dep_dict["name"] = parts[0].strip()
            dep_dict["operator"] = d
            dep_dict["version"] = parts[1].strip()

            return dep_dict

    # No operator/version specified
    dep_dict["name"] = st

    return dep_dict


def get_db():

    db = SessionLocal()

    try:
        yield db

    finally:
        db.close()


def get_dependency_path(owner, repo, branch):

    url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"

    response = requests.get(url)
    response.raise_for_status()

    data = response.json()

    paths = []
    tree = data["tree"]

    for d in tree:

        if d["type"] == "blob":

            file_name = d["path"].split("/")[-1]

            if file_name in MANIFEST_FILES:
                paths.append(d["path"])

    return paths


def get_file_content(owner, repo, path):

    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"

    response = requests.get(url)

    if response.status_code != 200:

        print("Error:", response.status_code)

        return None

    data = response.json()

    content = base64.b64decode(
        data["content"]
    ).decode("utf-8")

    return content


def parse_content(content):

    lines = content.splitlines()

    dependencies = []

    for line in lines:

        dependency = parsing(line)

        if dependency is not None:
            dependencies.append(dependency)

    return dependencies


def scan_github_url(scanned_repo: RepositoryRequest):

    parsed_url = urlparse(scanned_repo.url)

    ownerAndrepo = parsed_url.path.strip("/").split("/")

    if len(ownerAndrepo) < 2:
        raise ValueError("Invalid GitHub Repository!")

    owner = ownerAndrepo[0]
    repository = ownerAndrepo[1]

    return owner, repository


def scan_repository(db, owner, repository, scanned_repo: RepositoryRequest):

    vulnerability_results = {}
    all_vulnerabilities = []

    api_url = f"https://api.github.com/repos/{owner}/{repository}"

    response = requests.get(api_url)
    response.raise_for_status()

    response_dict = response.json()

    branch = response_dict["default_branch"]

    paths = get_dependency_path(
        owner,
        repository,
        branch
    )

    final_dependency_list = []

    for path in paths:

        file_name = path.split("/")[-1]

        ecosystem = MANIFEST_FILES[file_name]

        content = get_file_content(
            owner,
            repository,
            path
        )

        dependencies = parse_content(content)

        if ecosystem == "PyPI":

            graph = create_dependency_graph(
                dependencies
            )

            # print("\nNODES")

            # for node, data in graph.nodes(data=True):
            #     print(node, data)

            # print("\nDEPENDENCY ANALYSIS")

            for node in graph.nodes:

                if node == "project":
                    continue

                result = analyze_dependency(
                    graph,
                    node
                )

                # print(result)


                if result["version_known"]:

                    vulnerabilities = query_vulnerability(
                        result["dependency"],
                        ecosystem,
                        result["version"]
                    )

                    # print(
                    #     "VULNERABILITIES:",
                    #     vulnerabilities
                    # )

                elif result["specifier"] is not None:

                    vulnerabilities = query_dependency_range(
                        result["dependency"],
                        ecosystem,
                        result["specifier"]
                    )

                    # print(
                    #     "POTENTIAL VULNERABILITIES:",
                    #     vulnerabilities
                    # )

                else:

                    vulnerabilities = []

                enriched = enrich_vulnerabilities(
                graph,
                result["dependency"],
                vulnerabilities
            )

                all_vulnerabilities.extend(enriched)

                vulnerability_results[result["dependency"]] = enriched

        ecosystem_dict = {
            "ecosystem": ecosystem,
            "filename": file_name,
            "dependencies": dependencies
        }

        final_dependency_list.append(
            ecosystem_dict
        )

    security_score = get_security_score(
        all_vulnerabilities
    )

    security_level = get_security_level(
        security_score
    )

    print(
        "\nSECURITY SCORE:",
        security_score
    )

    print(
        "SECURITY LEVEL:",
        security_level
    )

    db_dependencies = []

    for ecosystem_data in final_dependency_list:

        ecosystem = ecosystem_data["ecosystem"]

        for dependency in ecosystem_data["dependencies"]:

            db_dep = models.Dependencies(
                name=dependency["name"],
                version=dependency["version"],
                ecosystem=ecosystem
            )

            db_dependencies.append(
                db_dep
            )

    result = insertData(
        db,
        owner,
        scanned_repo.url,
        db_dependencies,
        vulnerability_results
    )

    dependency_count = sum(
        len(ecosystem_data["dependencies"])
        for ecosystem_data in final_dependency_list
    )

    return {
        "scan_id": result["scan_id"],
        "repository": f"{owner}/{repository}",
        "dependencies": dependency_count,
        "vulnerabilities": result["vuln_count"],
        "security_score": security_score,
        "security_level": security_level
    }


@app.post("/scan")
def scan_url(
    repo: RepositoryRequest,
    db: Session = Depends(get_db)
):

    owner, repository = scan_github_url(repo)

    result = scan_repository(
        db,
        owner,
        repository,
        repo
    )

    return result

@app.get("/scan/{id}")
def scan_id(id: int):

    db = SessionLocal()

    try:

        # -----------------------------
        # Find scan
        # -----------------------------

        scan = db.query(models.Scans).filter(
            models.Scans.id == id
        ).first()


        if scan is None:

            return {
                "error": f"Scan {id} not found"
            }


        # -----------------------------
        # Get dependencies
        # -----------------------------

        dependencies = scan.dependencies


        # -----------------------------
        # Count vulnerabilities
        # -----------------------------

        vuln_count = 0

        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "unknown": 0
        }


        # -----------------------------
        # Prepare vulnerabilities
        # for security score
        # -----------------------------

        score_vulnerabilities = []


        for dependency in dependencies:

            for vulnerability in dependency.vulnerabilities:

                # Count vulnerability
                vuln_count += 1


                # -------------------------
                # Severity counting
                # -------------------------

                severity = vulnerability.severity

                if severity == "CRITICAL":

                    severity_counts["critical"] += 1

                elif severity == "HIGH":

                    severity_counts["high"] += 1

                elif severity == "MODERATE":

                    severity_counts["medium"] += 1

                elif severity == "LOW":

                    severity_counts["low"] += 1

                else:

                    severity_counts["unknown"] += 1


                # -------------------------
                # Data required by
                # get_security_score()
                # -------------------------

                score_vulnerabilities.append({

                    "severity": vulnerability.severity,

                    "depth": vulnerability.depth,

                    "dependency_type":
                        vulnerability.dependency_type

                })


        # -----------------------------
        # Calculate security score
        # -----------------------------

        security_score = get_security_score(
            score_vulnerabilities
        )


        # -----------------------------
        # Calculate security level
        # -----------------------------

        security_level = get_security_level(
            security_score
        )


        # -----------------------------
        # Dashboard response
        # -----------------------------

        result = {

            "id": scan.id,

            "repository": scan.repository.url,

            "scan_time": scan.created_at,

            "finished_at": scan.finished_at,

            "status": scan.status,

            "dependencies": len(dependencies),

            "vulnerabilities": vuln_count,

            "severity": severity_counts,

            "security_score": round(
                security_score,
                2
            ),

            "security_level": security_level
        }


        return result


    finally:

        db.close()

@app.get("/scan/{id}/vulnerabilities")
def scan_vulnerabilities(id: int):

    db = SessionLocal()

    try:

        scan = db.query(models.Scans).filter(
            models.Scans.id == id
        ).first()

        if scan is None:
            return {
                "error": f"Scan {id} not found"
            }

        vulnerabilities = []

        for dependency in scan.dependencies:

            for vulnerability in dependency.vulnerabilities:

                vulnerabilities.append({

                    "id": vulnerability.osv_id,

                    "summary": vulnerability.summary,

                    "severity": vulnerability.severity,

                    "dependency": dependency.name,

                    "version": dependency.version,

                    "ecosystem": dependency.ecosystem,

                    "dependency_type":
                        vulnerability.dependency_type,

                    "depth":
                        vulnerability.depth,

                    "fixed_version":
                        vulnerability.fixed_version

                })

        return {
            "scan_id": scan.id,
            "count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities
        }

    finally:

        db.close()