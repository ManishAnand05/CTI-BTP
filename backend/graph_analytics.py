from backend.database import get_connection

def analyze_graph_centrality():
    """
    Calculates PageRank and Degree Centrality using pure Python (no external libraries).
    """
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT org.name as org_name, rec.indicator_value
            FROM cti_submissions sub
            JOIN organizations org ON sub.organization_id = org.id
            JOIN cti_records rec ON sub.cti_record_id = rec.id
        """).fetchall()

    if not rows:
        return {"error": "Not enough graph data to analyze"}

    # 1. Build the Graph (Adjacency List)
    graph = {}
    for row in rows:
        org = row["org_name"]
        ioc = row["indicator_value"]
        
        if org not in graph: graph[org] = set()
        if ioc not in graph: graph[ioc] = set()
        
        graph[org].add(ioc)
        graph[ioc].add(org)

    num_nodes = len(graph)
    if num_nodes == 0:
        return {"error": "Not enough graph data to analyze"}

    # 2. Calculate PageRank (Iterative method)
    # Initialize all nodes with equal rank
    ranks = {node: 1.0 / num_nodes for node in graph}
    damping_factor = 0.85
    num_iterations = 20

    for _ in range(num_iterations):
        new_ranks = {}
        for node in graph:
            rank_sum = 0
            # Sum the ranks of all connected nodes, divided by their number of connections
            for neighbor in graph[node]:
                rank_sum += ranks[neighbor] / len(graph[neighbor])
            
            # PageRank formula
            new_ranks[node] = (1 - damping_factor) / num_nodes + (damping_factor * rank_sum)
        
        ranks = new_ranks

    # 3. Sort nodes by PageRank score
    sorted_nodes = sorted(ranks.items(), key=lambda x: x[1], reverse=True)

    top_nodes = []
    for node, score in sorted_nodes[:5]:
        top_nodes.append({
            "node": node,
            "pagerank_score": round(score, 4),
            "connections": len(graph[node])
        })

    return {
        "total_nodes": num_nodes,
        "total_edges": sum(len(neighbors) for neighbors in graph.values()) // 2,
        "most_influential_nodes": top_nodes
    }