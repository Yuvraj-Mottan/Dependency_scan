from app.dependency_graph import analyze_dependency

SEVERITY_WEIGHTS={"CRITICAL":10,"HIGH":7,"MODERATE":4,"LOW":1}

DEPENDENCY_MULTIPLIER = {
    "direct": 1.5,
    "transitive": 1.0
}


def depth_multiplier(depth=1):
    return 1 / (1 + 0.1 * depth)

def get_risk(severity,dep_type,depth):
    if not severity:
        return 0
    return SEVERITY_WEIGHTS.get(severity.upper(),0)*DEPENDENCY_MULTIPLIER.get(dep_type,1.0)*depth_multiplier(depth)

def get_security_score(vulnerabilities):
    if not vulnerabilities:
        return 100.0
    total_risk=0
    for vuln in vulnerabilities:
        severity=vuln["severity"]
        depth=vuln["depth"]
        vuln_type=vuln["dependency_type"]
        total_risk+=get_risk(severity,vuln_type,depth)

    max_risk=len(vulnerabilities)*15.0
    return max(0,100-total_risk/max_risk*100)

def get_security_level(score):
    if(score>=90):
        return "LOW"
    elif(score>=70):
        return "MEDIUM"
    elif score>=40:
        return "HIGH"
    return "CRITICAL"

def enrich_vulnerabilities(graph, dependency, vulnerabilities):

    analysis = analyze_dependency(graph, dependency)

    if analysis is None:
        return []

    result = []

    for vuln in vulnerabilities:

        result.append({
            "id": vuln["id"],
            "summary": vuln["summary"],
            "severity": vuln["severity"],
            "dependency": dependency,
            "dependency_type": analysis["type"],
            "depth": analysis["depth"]
        })

    return result

