from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy import ForeignKey
from sqlalchemy.orm import DeclarativeBase 
from sqlalchemy.orm import relationship
class Base(DeclarativeBase):
    pass

class Repository(Base):
    __tablename__="repositories"
    id=Column(Integer,primary_key=True)
    url=Column(String,nullable=False)
    name=Column(String,nullable=False)
    created_at=Column(DateTime)

    scans=relationship("Scans",back_populates="repository")


class Scans(Base):
    __tablename__="scans"
    id=Column(Integer,primary_key=True)
    repository_id=Column(Integer,ForeignKey("repositories.id"),nullable=False)
    status=Column(String,nullable=False)
    created_at=Column(DateTime)
    finished_at=Column(DateTime)
    repository = relationship("Repository", back_populates="scans") 
    dependencies = relationship("Dependencies", back_populates="scan")


class Dependencies(Base):
    __tablename__="dependencies"
    id=Column(Integer,primary_key=True)
    scan_id=Column(Integer,ForeignKey("scans.id"),nullable=False)
    name=Column(String,nullable=False)
    version=Column(String,nullable=True)
    ecosystem=Column(String,nullable=False)

    scan = relationship("Scans", back_populates="dependencies") 
    vulnerabilities = relationship( "Vulnerabilities", back_populates="dependency" )


class Vulnerabilities(Base):
    __tablename__="vulnerabilities"
    id=Column(Integer,primary_key=True)
    dependency_id=Column(Integer,ForeignKey("dependencies.id"),nullable=False)
    osv_id=Column(String)
    summary=Column(String)
    severity=Column(String)
    fixed_version=Column(String)
    dependency_type = Column(String)
    depth = Column(Integer)

    dependency = relationship( "Dependencies", back_populates="vulnerabilities" )

