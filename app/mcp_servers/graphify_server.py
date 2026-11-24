import re
from collections import deque
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

VAULT_DIR = Path(__file__).resolve().parents[2] / "knowledge_vault"
WIKILINK_RE = re.compile(r"\[\[([^\]|#]+)")
TENANT_RE = re.compile(r"[A-Za-z0-9_-]{1,128}")

mcp = FastMCP("graphify-vault")


def parse_note(text: str) -> tuple[dict[str, str], str]:
    """Split YAML-style frontmatter (flat key: value pairs) from the note body."""
    if not text.startswith("---"):
        return {}, text
    parts = text.split("---", 2)
    if len(parts) < 3:
        return {}, text
    meta: dict[str, str] = {}
    for line in parts[1].splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            meta[key.strip()] = value.strip().strip('"').strip("'")
    return meta, parts[2]


def load_tenant_notes(vault_dir: Path, tenant_id: str) -> dict[str, dict[str, Any]]:
    """Load only notes whose frontmatter tenant_id matches. Notes without a tenant_id are never returned."""
    notes: dict[str, dict[str, Any]] = {}
    for path in sorted(vault_dir.glob("*.md")):
        meta, body = parse_note(path.read_text(encoding="utf-8"))
        if meta.get("tenant_id") != tenant_id:
            continue
        node_id = meta.get("id", path.stem)
        notes[node_id] = {
            "id": node_id,
            "file": path.stem,
            "domain": meta.get("domain", ""),
            "risk_tier": meta.get("risk_tier", ""),
            "version": meta.get("version", ""),
            "links": [link.strip() for link in WIKILINK_RE.findall(body)],
        }
    return notes


def build_subgraph(vault_dir: Path, tenant_id: str, anchor: str, depth: int) -> dict[str, Any]:
    """Breadth-first traversal of [[wikilinks]] from the anchor, limited to depth hops, inside one tenant's notes."""
    notes = load_tenant_notes(vault_dir, tenant_id)
    by_name: dict[str, str] = {}
    for node_id, note in notes.items():
        by_name[node_id] = node_id
        by_name.setdefault(note["file"], node_id)

    start = by_name.get(anchor)
    if start is None:
        return {"tenant_id": tenant_id, "anchor": anchor, "depth": depth, "nodes": [], "edges": []}

    visited = {start: 0}
    edges: list[dict[str, str]] = []
    queue: deque[str] = deque([start])
    while queue:
        current = queue.popleft()
        if visited[current] >= depth:
            continue
        for link in notes[current]["links"]:
            target = by_name.get(link)
            if target is None:
                continue  # dangling link or link to another tenant's note: dropped
            edge = {"source": current, "target": target}
            if edge not in edges:
                edges.append(edge)
            if target not in visited:
                visited[target] = visited[current] + 1
                queue.append(target)

    nodes = [
        {"id": node_id, "domain": notes[node_id]["domain"], "risk_tier": notes[node_id]["risk_tier"],
         "version": notes[node_id]["version"], "hop": hop}
        for node_id, hop in sorted(visited.items(), key=lambda item: (item[1], item[0]))
    ]
    return {"tenant_id": tenant_id, "anchor": anchor, "depth": depth, "nodes": nodes, "edges": edges}


@mcp.tool()
def graphify_subgraph(tenant_id: str, anchor: str, depth: int = 2) -> dict:
    """Return the tenant-scoped wikilink subgraph around an anchor note, at most 2 hops deep."""
    if not TENANT_RE.fullmatch(tenant_id):
        raise ValueError("INVALID_TOOL_ARGUMENT: tenant_id")
    if not anchor or len(anchor) > 128:
        raise ValueError("INVALID_TOOL_ARGUMENT: anchor")
    return build_subgraph(VAULT_DIR, tenant_id, anchor, min(max(depth, 1), 2))


if __name__ == "__main__":
    mcp.run(transport="stdio")
