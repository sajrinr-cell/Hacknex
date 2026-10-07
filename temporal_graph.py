import networkx as nx


def build_temporal_graph(events):
    graph = nx.DiGraph()

    events = sorted(
        events,
        key=lambda event: event.corrected_timestamp
    )

    for event in events:
        graph.add_node(
            event.event_id,
            source=event.source,
            timestamp=event.corrected_timestamp,
            user=event.user,
            device=event.device,
            ip=event.ip,
            action=event.action,
            object=event.object,
            confidence=event.confidence
        )

    for i in range(len(events) - 1):
        current = events[i]
        next_event = events[i + 1]

        if (
            current.user == next_event.user
            and current.device == next_event.device
        ):
            graph.add_edge(
                current.event_id,
                next_event.event_id
            )

    return graph