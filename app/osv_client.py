import requests
from packaging.specifiers import SpecifierSet
from packaging.version import Version
from app.redis_client import redis_client
import json

def get_cache_key(ecosystem,name,version):
    return f"vulnerability:{ecosystem.lower()}:{name.lower()}:{version}"

def ranges_overlap(spec1, spec2):
    s1 = SpecifierSet(spec1)
    s2 = SpecifierSet(spec2)

    for a in s1:
        for b in s2:

            if a.operator in (">", ">=") and b.operator in ("<", "<="):
                if Version(a.version) < Version(b.version):
                    return True

            if b.operator in (">", ">=") and a.operator in ("<", "<="):
                if Version(b.version) < Version(a.version):
                    return True

    return False

def query_vulnerability(name,ecosystem,version):
    cache_key=get_cache_key(ecosystem,name,version)
    cached=redis_client.get(cache_key)

    if cached:
        print("Cache HIT: ",cache_key)
        return json.loads(cached)

    print("Cache Miss:",cache_key)

    data={"package":
          {
              "name":name,
              "ecosystem":ecosystem
          },"version":version}
    try:
        response=requests.post("https://api.osv.dev/v1/query",json=data)
        response.raise_for_status()
        result=response.json()
        # print(result)
        vulnerability=result.get("vulns",[])
        vuln_list=[]
        for vuln in vulnerability:
            vuln_dict=dict({})
            vuln_dict["id"]=vuln["id"]
            vuln_dict["summary"]=vuln.get("summary",None)
            vuln_dict["severity"]=None
            if vuln.get("database_specific") is not None:
                vuln_dict["severity"]=vuln.get("database_specific").get("severity",None)

            fixed_version = None

            for affected in vuln.get("affected", []):
                for range_data in affected.get("ranges", []):
                    for event in range_data.get("events", []):
                        if "fixed" in event:
                            fixed_version = event["fixed"]
                            break
    # affected->ranges->events->list(fixed)
            vuln_dict["fixed_version"]=fixed_version
            vuln_list.append(vuln_dict)

        redis_client.set(cache_key,json.dumps(vuln_list),ex=86400)
        print("Cache stored:",cache_key)
            
        return vuln_list
    
    except requests.RequestException as e:
        print(f"OSV Error:{e}")
        return []

result=query_vulnerability("requests","PyPI","2.25.1")
# print(result)

def query_dependency_range(name, ecosystem, specifier):

    data = {
        "package": {
            "name": name,
            "ecosystem": ecosystem
        }
    }

    response = requests.post(
        "https://api.osv.dev/v1/query",
        json=data
    )

    response.raise_for_status()

    vulnerabilities = response.json().get("vulns", [])

    result = []
    seen=set()
    for vuln in vulnerabilities:

        for affected in vuln.get("affected", []):

            for range_data in affected.get("ranges", []):
                if range_data.get("type") != "ECOSYSTEM":
                    continue
                introduced = None
                fixed = None

                for event in range_data.get("events", []):

                    if "introduced" in event:
                        introduced = event["introduced"]

                    if "fixed" in event:
                        fixed = event["fixed"]

                if introduced is None or fixed is None:
                    continue

                vuln_range = f">={introduced},<{fixed}"

                if ranges_overlap(specifier, vuln_range):
                    if vuln["id"] in seen:
                        continue

                    seen.add(vuln["id"])

                    result.append({
                        "id": vuln["id"],
                        "summary": vuln.get("summary"),
                        "severity": vuln.get("database_specific", {}).get("severity"),
                        "status": "potential"
                    })  

    return result

if __name__=="__main__":    
    result = query_dependency_range(
        "urllib3",
        "PyPI",
        ">=1.21.1,<3"
    )

    print(result)