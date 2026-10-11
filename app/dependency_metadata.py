import requests
from packaging.requirements import Requirement
import networkx as nx

def get_package_dependencies(package,version):
    url=f"https://pypi.org/pypi/{package}/{version}/json"
    response=requests.get(url,timeout=10)

    if response.status_code!=200:
        return []

    data=response.json()
    requires_dist=data["info"].get("requires_dist")
    if not requires_dist:
        return []
    final_package_list=[]
    for pack in requires_dist:
        req=Requirement(pack)
        if "extra ==" in str(req.marker):
            continue
        d = {
    "name": req.name,
    "specifier": str(req.specifier),
    "marker": str(req.marker) if req.marker else None
}
        final_package_list.append(d)

    return final_package_list
