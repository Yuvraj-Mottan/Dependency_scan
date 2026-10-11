from sqlalchemy import create_engine
from app import models
import datetime
from sqlalchemy.orm import sessionmaker
import os
from dotenv import load_dotenv


load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("DATABASE_URL is not set in .env")


engine = create_engine(DATABASE_URL)
# models.Base.metadata.drop_all(engine)
models.Base.metadata.create_all(engine)

SessionLocal = sessionmaker(bind=engine)


def insertInRepo(repo: models.Repository):

    db = SessionLocal()

    try:

        repo.created_at = datetime.datetime.now()

        db.add(repo)
        db.commit()
        db.refresh(repo)

        return repo

    except Exception as e:

        db.rollback()
        raise e

    finally:

        db.close()


def insertInScan(scan: models.Scans):

    db = SessionLocal()

    try:

        scan.created_at = datetime.datetime.now()

        db.add(scan)
        db.commit()
        db.refresh(scan)

        return scan

    except Exception as e:

        db.rollback()
        raise e

    finally:

        db.close()


def insertData(
    db,
    owner,
    url,
    dependencies,
    vulnerability_results
):

    try:

        repo = models.Repository(
            name=owner,
            url=url
        )

        repo.created_at = datetime.datetime.now()

        db.add(repo)
        db.flush()

        scan = models.Scans(
            repository_id=repo.id,
            status="complete"
        )

        scan.created_at = datetime.datetime.now()

        db.add(scan)
        db.flush()

        vuln_count = 0

        for dep in dependencies:

            dep.scan_id = scan.id

            db.add(dep)
            db.flush()

            # Get vulnerabilities for
            # this dependency
            vuln_list = vulnerability_results.get(
                dep.name,
                []
            )

            for vuln_val in vuln_list:

                vuln_count += 1

                vuln = models.Vulnerabilities(
                    dependency_id=dep.id,

                    osv_id=vuln_val.get("id"),

                    summary=vuln_val.get("summary"),

                    severity=vuln_val.get("severity"),

                    fixed_version=vuln_val.get(
                        "fixed_version"
                    ),

                    dependency_type=vuln_val.get(
                        "dependency_type"
                    ),

                    depth=vuln_val.get(
                        "depth"
                    )
                )

                db.add(vuln)

        scan.finished_at = datetime.datetime.now()
        db.commit()

        return {
            "scan_id": scan.id,
            "vuln_count": vuln_count
        }

    except Exception as e:

        db.rollback()
        raise e

    finally:

        db.close()