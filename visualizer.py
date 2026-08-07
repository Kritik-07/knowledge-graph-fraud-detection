"""
visualizer.py
-------------
Presentation-ready Knowledge Graph visualisation.

Static PNG  → matplotlib  (print / report quality)
Interactive → PyVis HTML  (browser, zoom/pan/hover)

Design goals:
  • Legible node labels (no underscores, clean fonts)
  • Colour-coded node types with strong contrast
  • Suspicious nodes: vivid red ring + glow
  • Edge labels: bright coloured text, dark halo — NO white box
  • Professional dark-cyber theme
  • Clean layout, no overlap
"""
from __future__ import annotations

import os
from platform import node
from platform import node
import textwrap
from typing import Optional

import networkx as nx
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.colors as mcolors

from logger import get_logger

logger = get_logger(__name__)

# ── palette ───────────────────────────────────────────────────────────────────

BG          = "#0D1117"
PANEL       = "#161B22"
BORDER      = "#30363D"
TEXT_MAIN   = "#E6EDF3"
TEXT_DIM    = "#8B949E"

NODE_STYLE: dict[str, dict] = {
    "customer":    {"color": "#2F88FF", "size": 1100, "label_color": "#FFFFFF"},
    "ip":          {"color": "#FF4560", "size":  850, "label_color": "#FFFFFF"},
    "device":      {"color": "#00E396", "size":  850, "label_color": "#111111"},
    "transaction": {"color": "#FEB019", "size":  700, "label_color": "#111111"},
}
DEFAULT_STYLE = {"color": "#8B949E", "size": 600, "label_color": "#FFFFFF"}

EDGE_PALETTE: dict[str, str] = {
    "payment":     "#FEB019",
    "from_ip":     "#FF4560",
    "uses_device": "#00E396",
}
EDGE_LINE_ALPHA = 0.75

ALERT_COLOR      = "#FF3A3A"
ALERT_RING_SCALE = 2.6
ALERT_LW         = 4.0
NORMAL_LW        = 1.0

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))


# ── label helpers ─────────────────────────────────────────────────────────────

def _clean(label: str, maxlen: int = 14) -> str:
    """
    Make node labels human-readable:
      • Replace underscores with spaces
      • Shorten very long strings
      • Capitalise first letter
    """
    s = label.replace("_", " ").strip()
    # Keep IPs and UUIDs compact
    if len(s) > maxlen:
        s = s[:maxlen - 1] + "…"
    return s


def _edge_label_clean(rel: str) -> str:
    return rel.replace("_", " ")


# ─────────────────────────────────────────────────────────────────────────────
# Static PNG
# ─────────────────────────────────────────────────────────────────────────────

def _choose_layout(sg: nx.Graph) -> dict:
    """Pick the best layout based on graph size."""
    n = sg.number_of_nodes()
    if n <= 30:
        return nx.spring_layout(sg, k=4.5, iterations=120, seed=42)
    if n <= 80:
        return nx.spring_layout(sg, k=3.0, iterations=80,  seed=42)
    # Large graphs: kamada_kawai gives cleaner separation
    try:
        return nx.spring_layout(
    sg,
    k=1.8,
    iterations=120,
    seed=42
)
    except Exception:
        return nx.spring_layout(sg, k=2.0, iterations=60, seed=42)


def visualize_graph_static(
    
    graph: nx.DiGraph,
    highlight_nodes: Optional[list[str]] = None,
    output_path: Optional[str] = None,
    title: str = "Knowledge Graph — Cyber Threat Detection",
    filter_customer: Optional[str] = None,
    suspicious_only: bool = False,
    focus_node: Optional[str] = None
) -> str:
    hl: set[str] = set(highlight_nodes or [])

    # ── subgraph ──────────────────────────────────────────────────────────────
    # 🔥 ALWAYS focus on highlighted nodes (transaction + related)
    # 🔥 FOCUS ONLY ON CURRENT TRANSACTION NODE
    if focus_node and graph.has_node(focus_node):
        keep = set([focus_node])
        keep.update(graph.predecessors(focus_node))
        keep.update(graph.successors(focus_node))

        sg = graph.subgraph(keep)
    else:
        sg = graph

    if not sg.nodes:
        logger.warning("Empty subgraph — nothing to render.")
        return ""

    pos = _choose_layout(sg)
    plt.figure(figsize=(12, 10), facecolor="#0D1117")

    # ── classify nodes ────────────────────────────────────────────────────────
    node_list   = list(sg.nodes())
    colors      = [NODE_STYLE.get(sg.nodes[n].get("type",""), DEFAULT_STYLE)["color"]
                   for n in node_list]
    sizes       = [NODE_STYLE.get(sg.nodes[n].get("type",""), DEFAULT_STYLE)["size"]
                   for n in node_list]
    edgecolors  = [ALERT_COLOR if n in hl else BORDER for n in node_list]
    linewidths  = [ALERT_LW   if n in hl else NORMAL_LW for n in node_list]

    # ── figure ────────────────────────────────────────────────────────────────
    fig_w = max(18, sg.number_of_nodes() * 0.6)
    fig_h = max(12, sg.number_of_nodes() * 0.4)
    fig, ax = plt.subplots(figsize=(min(fig_w, 28), min(fig_h, 20)),
                           facecolor=BG)
    ax.set_facecolor(BG)
    ax.set_title(title, color=TEXT_MAIN, fontsize=16,
                 fontweight="bold", pad=20, fontfamily="DejaVu Sans")

    # Draw glow rings for suspicious nodes (outer ring, bigger, alpha)
    sus_list = [n for n in node_list if n in hl]
    if sus_list:
        sus_sizes  = [NODE_STYLE.get(sg.nodes[n].get("type",""), DEFAULT_STYLE)["size"] * ALERT_RING_SCALE
                      for n in sus_list]
        nx.draw_networkx_nodes(
            sg, pos, nodelist=sus_list, ax=ax,
            node_color=ALERT_COLOR,
            node_size=sus_sizes,
            alpha=0.20,
        )

    # Main nodes
    nx.draw_networkx_nodes(
        sg, pos, nodelist=node_list, ax=ax,
        node_color=colors,
        node_size=sizes,
        edgecolors=edgecolors,
        linewidths=linewidths,
        alpha=0.96,
    )

    # ── edges grouped by relation ─────────────────────────────────────────────
    rel_edges: dict[str, list[tuple[str, str]]] = {}
    for u, v, d in sg.edges(data=True):
        rel = d.get("relation", "")
        rel_edges.setdefault(rel, []).append((u, v))

    edge_draw_colors = {
        "payment":     "#FEB01988",
        "from_ip":     "#FF456088",
        "uses_device": "#00E39688",
    }
    for rel, elist in rel_edges.items():
        nx.draw_networkx_edges(
            sg, pos, edgelist=elist, ax=ax,
            edge_color=edge_draw_colors.get(rel, "#8B949E55"),
            arrows=True, arrowsize=20, width=1.8,
            alpha=EDGE_LINE_ALPHA,
            connectionstyle="arc3,rad=0.10",
            min_source_margin=20, min_target_margin=20,
        )

    # ── node labels ───────────────────────────────────────────────────────────
    labels = {n: _clean(str(n)) for n in sg.nodes()}
    nx.draw_networkx_labels(
        sg, pos, labels=labels, ax=ax,
        font_size=8,
        font_color=TEXT_MAIN,
        font_weight="bold",
        font_family="DejaVu Sans",
    )

    # ── edge labels — dark box + bright coloured text ─────────────────────────
    for rel, elist in rel_edges.items():
        edge_lbl   = {(u, v): _edge_label_clean(rel) for u, v in elist}
        txt_color  = EDGE_PALETTE.get(rel, TEXT_DIM)
        nx.draw_networkx_edge_labels(
            sg, pos, edge_labels=edge_lbl, ax=ax,
            font_size=7,
            font_color=txt_color,
            font_weight="bold",
            font_family="DejaVu Sans",
            label_pos=0.40,
            bbox=dict(
                boxstyle="round,pad=0.25",
                facecolor=PANEL,
                edgecolor=txt_color,
                alpha=0.88,
                linewidth=0.9,
            ),
        )

    # ── legend ────────────────────────────────────────────────────────────────
    node_patches = [
        mpatches.Patch(color=NODE_STYLE["customer"]["color"],    label="Customer"),
        mpatches.Patch(color=NODE_STYLE["ip"]["color"],          label="IP Address"),
        mpatches.Patch(color=NODE_STYLE["device"]["color"],      label="Device"),
        mpatches.Patch(color=NODE_STYLE["transaction"]["color"], label="Transaction"),
        mpatches.Patch(color=ALERT_COLOR, label="⚠  Suspicious / Fraud"),
    ]
    edge_patches = [
        mpatches.Patch(color=EDGE_PALETTE["payment"],     label="payment"),
        mpatches.Patch(color=EDGE_PALETTE["from_ip"],     label="from IP"),
        mpatches.Patch(color=EDGE_PALETTE["uses_device"], label="uses device"),
    ]
    legend = ax.legend(
        handles=node_patches + edge_patches,
        loc="lower left",
        facecolor=PANEL,
        edgecolor=BORDER,
        labelcolor=TEXT_MAIN,
        fontsize=9,
        title="Legend",
        title_fontsize=10,
        framealpha=0.90,
    )
    legend.get_title().set_color(TEXT_MAIN)

    ax.axis("off")
    plt.tight_layout(pad=1.5)

    out = output_path or os.path.join(OUTPUT_DIR, "knowledge_graph.png")
    plt.savefig(out, dpi=160, bbox_inches="tight", facecolor=BG)
    plt.close(fig)
    logger.info(f"Static PNG → {out}")
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Interactive HTML (PyVis)
# ─────────────────────────────────────────────────────────────────────────────

_PYVIS_SHAPES: dict[str, str] = {
    "customer":    "dot",
    "ip":          "diamond",
    "device":      "square",
    "transaction": "triangle",
}
_PYVIS_SIZES: dict[str, int] = {
    "customer": 26, "ip": 20, "device": 20, "transaction": 16,
}
_PYVIS_EDGE_COLORS: dict[str, dict] = {
    "payment":     {"color": "#FEB019", "highlight": "#FFD366"},
    "from_ip":     {"color": "#FF4560", "highlight": "#FF8FA0"},
    "uses_device": {"color": "#00E396", "highlight": "#66F2BC"},
}


def visualize_graph_interactive(
    graph: nx.DiGraph,
    highlight_nodes: Optional[list[str]] = None,
    flagged_nodes: Optional[list[str]] = None,
    output_path: Optional[str] = None,
    filter_customer: Optional[str] = None,
    suspicious_only: bool = False
) -> str:
    try:
        from pyvis.network import Network  # type: ignore
    except ImportError:
        logger.error("pyvis not installed: pip install pyvis")
        return ""

    # extract only node ids from highlight_nodes (dict or string safe)
    hl = set()

    if highlight_nodes:
        for r in highlight_nodes:
            if isinstance(r, dict):
                node_id = r.get("node")
                if node_id:
                    hl.add(str(node_id))
            else:
                hl.add(str(r))
    flagged = set(flagged_nodes or [])

    # ── subgraph ──────────────────────────────────────────────────────────────
    if suspicious_only and hl:
        keep: set[str] = set(hl)
        for n in list(hl):
            if graph.has_node(n):
                keep.update(graph.predecessors(n))
                keep.update(graph.successors(n))
        sg = graph.subgraph(keep)
    else:
        sg = graph

    net = Network(
        height="860px", width="100%",
        bgcolor=BG, font_color=TEXT_MAIN,  # type: ignore
        directed=True, notebook=False,
    )
    net.barnes_hut(
        gravity=-10000, central_gravity=0.20,
        spring_length=220, spring_strength=0.035, damping=0.10,
        overlap=0,
    )

    # ── nodes ─────────────────────────────────────────────────────────────────
    for node, data in sg.nodes(data=True):
        ntype   = str(data.get("type", "customer"))
        style   = NODE_STYLE.get(ntype, DEFAULT_STYLE)

        is_flagged = node in flagged
        is_risk    = node in hl

        size = _PYVIS_SIZES.get(ntype, 16)

        # Tooltip
        tip  = [f"<b>{node}</b>", f"<i style='color:#8B949E'>Type: {ntype}</i>"]
        skip = {"type", "label"}
        for k, v in data.items():
            if k not in skip:
                tip.append(f"<span style='color:#C9D1D9'>{k}: <b>{v}</b></span>")
        tooltip = "<br>".join(tip)

        # 🔥 SAFE RISK EXTRACTION
        risk_map = {}
        risk_reason_map = {}

        if highlight_nodes:
            for r in highlight_nodes:
                if isinstance(r, dict):   # important fix
                    node_id = str(r.get("node")).strip()
                    if node_id:
                        risk_map[node_id] = r.get("risk")
                        risk_reason_map[node_id] = r.get("reason")

        node_key = str(node).strip()

        risk_value = risk_map.get(node_key)
        extra_reason = risk_reason_map.get(node_key)

        # 🔥 LABEL
        if risk_value:
            label_text = f"{_clean(str(node), 12)} ({risk_value}%)"
        else:
            label_text = _clean(str(node), 16)

        # 🔥 TOOLTIP
        if extra_reason:
            tooltip = tooltip + f"<br><br><b style='color:#A855F7'>Risk Reason:</b><br>{extra_reason}"

        # 🔥 NODE
        net.add_node(
            node,
            label=label_text,
            color={ #type: ignore
                "background": (
                    ALERT_COLOR if is_flagged else
                    "#A855F7" if is_risk else
                    style["color"]
                ),
                "border": (
                    ALERT_COLOR if is_flagged else
                    "#A855F7" if is_risk else
                    BORDER
                ),
                "highlight": {"background": style["color"], "border": "#FFD700"},
                "hover": {"background": style["color"], "border": "#FFD700"},
            },
            size=size,
            shape=_PYVIS_SHAPES.get(ntype, "dot"),
            title=tooltip,
            borderWidth=5 if is_flagged else (3 if is_risk else 1),
            borderWidthSelected=6,
            shadow={
                "enabled": is_flagged or is_risk,
                "color": ALERT_COLOR if is_flagged else "#A855F7",
                "size": 18,
            },
            font={
                "color": TEXT_MAIN,
                "size": 13,
                "bold": True,
                "face": "Arial, sans-serif",
                "background": "none",
                "strokeWidth": 4,
                "strokeColor": BG,
            },
        )

    # ── edges ─────────────────────────────────────────────────────────────────
    for u, v, data in sg.edges(data=True):
        rel = str(data.get("relation", ""))
        ec  = _PYVIS_EDGE_COLORS.get(rel, {"color": TEXT_DIM, "highlight": TEXT_MAIN})

        net.add_edge(
            u, v,
            label=_edge_label_clean(rel),
            color=ec,
            arrows={"to": {"enabled": True, "scaleFactor": 0.7}},
            font={
                "color":       ec["color"],
                "size":        11,
                "bold":        True,
                "face":        "Arial, sans-serif",
                "background":  "none",
                "strokeWidth": 4,
                "strokeColor": BG,
                "align":       "middle",
            },
            smooth={"type": "curvedCW", "roundness": 0.18},
            width=2.0,
            selectionWidth=4,
        )

    # ── physics / interaction options ─────────────────────────────────────────
    net.set_options("""
    {
      "edges": {
        "scaling": { "min": 1, "max": 5 }
      },
      "interaction": {
        "hover":         true,
        "tooltipDelay":  60,
        "zoomView":      true,
        "dragNodes":     true,
        "multiselect":   true,
        "navigationButtons": true
      },
      "physics": {
        "enabled":       true,
        "stabilization": { "iterations": 300, "updateInterval": 20 }
      }
    }
    """)

    out = output_path or os.path.join(OUTPUT_DIR, "knowledge_graph_interactive.html")
    net.save_graph(out)
    _patch_html(out)
    logger.info(f"Interactive HTML → {out}")
    return out


def _patch_html(path: str) -> None:
    try:
        with open(path, "r", encoding="utf-8") as f:
            html = f.read()
        # 🔥 CSP FIX
        inject_csp = """
        <meta http-equiv="Content-Security-Policy" content="script-src 'self' 'unsafe-inline' 'unsafe-eval' https:;">
        """

        html = html.replace("<head>", "<head>" + inject_csp)

        # 🔥 JS injection
        inject_script = """
<script>
window.addEventListener("message", function(event) {
    if (event.data.type === "SEARCH_NODE") {

        const value = event.data.value;

        if (!window.network || !window.nodes) {
            console.log("Graph not ready");
            return;
        }

        const allNodes = nodes.get();

        const matches = allNodes.filter(n =>
            (n.id && n.id.toLowerCase().includes(value.toLowerCase())) ||
            (n.label && n.label.toLowerCase().includes(value.toLowerCase()))
        );

        if (matches.length === 0) {
            alert("No matching nodes");
            return;
        }

        const ids = matches.map(n => n.id);

        network.selectNodes(ids);

        network.fit({
            nodes: ids,
            animation: true
        });
    }
});
</script>
"""

        # 🔥 CSS injection (THIS WAS YOUR ERROR PART)
        inject_css = """
<style>
#mynetwork {
  width: 100%;
  height: 100vh;
}

.vis-button {
  appearance: none;
  -webkit-appearance: none;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  float: none;
}

.vis-network canvas {
  background: #0D1117 !important;
}

* {
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

div.vis-tooltip {
  background: #161B22 !important;
  border: 1px solid #30363D !important;
  border-radius: 8px !important;
  color: #C9D1D9 !important;
  font-size: 12px !important;
  padding: 8px 12px !important;
}
</style>
"""

        # ✅ Inject CSS into <head>
        html = html.replace("</head>", inject_css + "\n</head>")

        # ✅ Inject JS into <body>
        html = html.replace("</body>", inject_script + "\n</body>")

        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    except Exception as exc:
        logger.warning(f"HTML patch failed: {exc}")
# ── public API ────────────────────────────────────────────────────────────────

def visualize_graph(
    graph: nx.DiGraph,
    highlight_nodes: Optional[list[str]] = None,
    flagged_nodes: Optional[list[str]] = None,   # ✅ ADD
    output_dir: Optional[str] = None,
    filter_customer: Optional[str] = None,
    suspicious_only: bool = False,
    focus_node: Optional[str] = None
) -> dict[str, str]:
    """
    Generate both static PNG and interactive HTML.
    Always reflects the CURRENT state of the graph (including dynamic adds).

    Args:
        graph:            Live nx.DiGraph from KnowledgeGraph.graph
        highlight_nodes:  Node IDs to flag red (auto-computed by engines)
        output_dir:       Save directory (defaults to same folder as this file)
        filter_customer:  Show ego-graph for one customer only
        suspicious_only:  Show only flagged nodes + 1-hop neighbours

    Returns:
        {"png": path, "html": path}
    """
    out_dir = output_dir or OUTPUT_DIR
    os.makedirs(out_dir, exist_ok=True)

    png_path  = os.path.join(out_dir, "knowledge_graph.png")
    html_path = os.path.join(out_dir, "knowledge_graph_interactive.html")
    results:  dict[str, str] = {}

    try:
        results["png"] = visualize_graph_static(
            graph,
            highlight_nodes=highlight_nodes,
            output_path=png_path,
            filter_customer=filter_customer,
            suspicious_only=suspicious_only,
            focus_node=focus_node   # ✅ PASS
        )
    except Exception as exc:
        logger.error(f"Static viz failed: {exc}")

    try:
        results["html"] = visualize_graph_interactive(
            graph, highlight_nodes=highlight_nodes,
            flagged_nodes=flagged_nodes, 
            output_path=html_path,
            filter_customer=filter_customer,
            suspicious_only=suspicious_only,
        )
    except Exception as exc:
        logger.error(f"Interactive viz failed: {exc}")

    return results


def regenerate_visualizations(
    kg,
    output_dir: Optional[str] = None,
    focus_node: Optional[str] = None,
    
    highlight_nodes: Optional[list[str]] = None
) -> dict[str, str]:

    # ✅ FIX 1: correct indentation
    highlight_nodes = highlight_nodes or []

    return visualize_graph(
    graph=kg.graph,
    highlight_nodes=highlight_nodes,                 # only propagated
    flagged_nodes=list(kg.flagged_nodes),            # only fraud
    output_dir=output_dir,
    filter_customer=None,
    focus_node=focus_node
)