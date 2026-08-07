import networkx as nx


class FraudStoryEngine:
    def __init__(self, graph: nx.DiGraph):
        self.graph = graph

    def reconstruct_story(self, transaction_id, triggered_rules, device=None, ip=None):
        """
        Generate fraud story for a transaction
        """

        if transaction_id not in self.graph:
            return "Transaction not found in graph"

        # Step 1: Get customer from transaction
        customer = self._get_incoming_neighbor(transaction_id, "payment")

        # Step 2: Get related entities
        if device is None:
            device = self._get_outgoing_neighbor(customer, "uses_device")

        if ip is None:
            ip = self._get_outgoing_neighbor(customer, "from_ip")

        # Step 3: Build timeline
        timeline = self._build_timeline(customer)

        # Step 4: Convert rules to explanation
        explanations = self._map_rules_to_explanation(triggered_rules)

        # Step 5: Generate story
        story = self._generate_story(
            transaction_id, customer, device, ip, timeline, explanations
        )

        return story

    # -----------------------------
    # Graph Traversal Helpers
    # -----------------------------

    def _get_outgoing_neighbor(self, node, relation):
        """
        For edges: node → neighbor
        """
        if node is None:
            return None

        for neighbor in self.graph.successors(node):
            edge_data = self.graph.get_edge_data(node, neighbor)
            if edge_data and edge_data.get("relation") == relation:
                return neighbor
        return None

    def _get_incoming_neighbor(self, node, relation):
        """
        For edges: neighbor → node
        """
        for neighbor in self.graph.predecessors(node):
            edge_data = self.graph.get_edge_data(neighbor, node)
            if edge_data and edge_data.get("relation") == relation:
                return neighbor
        return None

    # -----------------------------
    # Timeline Builder
    # -----------------------------

    def _build_timeline(self, customer):
        """
        Build chronological transaction timeline
        """
        events = []

        if customer is None:
            return events

        for neighbor in self.graph.successors(customer):
            edge_data = self.graph.get_edge_data(customer, neighbor)

            if edge_data and edge_data.get("relation") == "payment":
                timestamp = edge_data.get("timestamp")

                if timestamp:
                    events.append((timestamp, neighbor))

        # Sort by timestamp
        events.sort(key=lambda x: x[0])

        return events

    # -----------------------------
    # Rule Explanation Mapper
    # -----------------------------

    def _map_rules_to_explanation(self, rules):
        """
        Convert rule names → readable explanation
        """

        rule_explanations = {
            "velocity_fraud": "Multiple transactions occurred in a short period.",
            "high_value_outlier": "the transaction amount is unusually high compared to normal behavior",
            "location_change": "Sudden change in IP/location detected.",
            "shared_device": "Device has been used by multiple users.",
        }

        explanations = []

        for rule in rules:
            if rule in rule_explanations:
                explanations.append(rule_explanations[rule])
            else:
                explanations.append(f"{rule} triggered.")

        return explanations

    # -----------------------------
    # Story Generator
    # -----------------------------

    def _generate_story(self, tx, customer, device, ip, timeline, explanations):
        """
        Generate narrative-style fraud story (causal + human-like)
        """

        story = []

        # -----------------------------
        # Opening (Context)
        # -----------------------------
        story.append(f"🚨 Fraud Analysis Report for Transaction {tx}\n")

        story.append(
            f"The transaction under investigation involves customer {customer}, "
            f"operating from IP address {ip} using device {device}."
        )

        # -----------------------------
        # Timeline Narrative (Flow)
        # -----------------------------
        if timeline:
            story.append("\n📜 Sequence of Events:")

            for i, (time, event) in enumerate(timeline):
                if event == tx:
                    story.append(
                        f"→ At {time}, the suspicious transaction ({event}) was executed."
                    )
                elif i == 0:
                    story.append(
                        f"→ Earlier activity observed at {time}, indicating normal usage patterns."
                    )
                else:
                    story.append(
                        f"→ Follow-up activity recorded at {time}, continuing the interaction sequence."
                    )
        else:
            story.append(
                "\nNo historical transaction sequence was available for this customer."
            )

        # -----------------------------
        # Causal Reasoning (THIS IS KEY)
        # -----------------------------
        story.append("\n🧠 Behavioral Analysis:")

        if explanations:
            # Convert explanations into causal flow
            for i, exp in enumerate(explanations):
                if i == 0:
                    story.append(f"- Initially, {exp.lower()}")
                else:
                    story.append(f"- Additionally, {exp.lower()}")

        # -----------------------------
        # Causal Chain (NEW)
        # -----------------------------
        story.append("\n🔗 Causal Interpretation:")

        if len(explanations) >= 2:
            story.append(
                "The combination of these factors is not isolated. "
                "Instead, they form a connected pattern of anomalous behavior."
            )

            story.append(
                "The presence of shared infrastructure (device/IP), followed by unusual "
                "transaction characteristics, suggests a coordinated or unauthorized activity."
            )
        else:
            story.append(
                "Although limited indicators are present, the detected anomaly still deviates from normal behavior."
            )

        # -----------------------------
        # Conclusion (Human-like)
        # -----------------------------
        story.append("\n🧾 Final Assessment:")

        story.append(
            "Based on the sequence of events and the observed behavioral deviations, "
            "this transaction aligns with patterns commonly associated with fraudulent activity."
        )

        story.append(
            "The evidence suggests a potential compromise scenario, such as account takeover "
            "or misuse of shared access points."
        )

        return "\n".join(story)