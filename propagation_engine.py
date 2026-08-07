import networkx as nx


class RiskPropagationEngine:
    def __init__(self, graph: nx.DiGraph):
        self.graph = graph

    def propagate(self, start_customer: str):
        results = []

        if start_customer not in self.graph:
            return results

        # Step 1: find direct connections
        devices = []
        ips = []

        for neighbor in self.graph.successors(start_customer):
            edge = self.graph.get_edge_data(start_customer, neighbor)
            if not edge:
                continue

            if edge.get("relation") == "uses_device":
                devices.append(neighbor)

            elif edge.get("relation") == "from_ip":
                ips.append(neighbor)

        # Step 2: customers sharing SAME DEVICE (highest risk)
        for device in devices:
            for customer in self.graph.predecessors(device):
                if customer == start_customer:
                    continue

                results.append({
                    "node": customer,
                    "risk": 75,
                    "reason": f"Shares same device ({device})"
                })

        # Step 3: customers sharing SAME IP (medium risk)
        for ip in ips:
            for customer in self.graph.predecessors(ip):
                if customer == start_customer:
                    continue

                results.append({
                    "node": customer,
                    "risk": 65,
                    "reason": f"Shares same IP ({ip})"
                })

        # Step 4: indirect connections (lower risk)
        for device in devices:
            for customer in self.graph.predecessors(device):
                if customer == start_customer:
                    continue

                # second level: customers connected to that customer
                for next_node in self.graph.successors(customer):
                    edge = self.graph.get_edge_data(customer, next_node)

                    if edge and edge.get("relation") == "uses_device":
                        for indirect_customer in self.graph.predecessors(next_node):
                            if indirect_customer in (start_customer, customer):
                                continue

                            results.append({
                                "node": indirect_customer,
                                "risk": 40,
                                "reason": "Indirectly connected via shared device network"
                            })

        # Step 5: remove duplicates (keep highest risk)
        unique = {}
        for r in results:
            node = r["node"]
            if node not in unique or r["risk"] > unique[node]["risk"]:
                unique[node] = r

        final_results = list(unique.values())

        # Step 6: sort by risk
        final_results.sort(key=lambda x: x["risk"], reverse=True)

        return final_results[:5]