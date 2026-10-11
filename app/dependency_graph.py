import networkx as nx
from app.dependency_metadata import get_package_dependencies


def build_dependency_tree(package, version, graph, visited=None):

    if visited is None:
        visited = set()

    if package in visited:
        return

    visited.add(package)

    dependencies = get_package_dependencies(package, version)
    # print(package,version)
    # print(dependencies)
    for dependency in dependencies:

        name = dependency["name"]
        specifier = dependency["specifier"]

        graph.add_node(
            name,
            version=None,
            specifier=specifier,
            version_known=False
        )

        graph.add_edge(package, name)


def create_dependency_graph(dependencies):

    graph = nx.DiGraph()

    graph.add_node("project")

    for dependency in dependencies:

        name = dependency["name"]
        version = dependency["version"]
        if name not in graph:
            graph.add_node(
            name,
            version=version,
            specifier=None,
            version_known=version is not None
        )

        graph.add_edge("project", name)

        if version is not None:
            build_dependency_tree(
                name,
                version,
                graph
            )

    return graph


def get_dependency_path(graph, dependency):

    try:
        return nx.shortest_path(
            graph,
            "project",
            dependency
        )

    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return None


def get_dependency_type(graph, dependency):

    if dependency not in graph:
        return None

    if dependency in graph.successors("project"):
        return "direct"

    if nx.has_path(graph, "project", dependency):
        return "transitive"

    return None


def analyze_dependency(graph, dependency):

    if dependency not in graph:
        return None
    path=get_dependency_path(graph, dependency)
    return {
        "dependency": dependency,
        "type": get_dependency_type(graph, dependency),
        "version": graph.nodes[dependency].get("version"),
        "specifier": graph.nodes[dependency].get("specifier"),
        "version_known": graph.nodes[dependency].get("version_known"),
        "path": path,
        "depth" : len(path)-1
    }