from app.mcp_servers.graphify_server import build_subgraph


def _note(vault, name: str, tenant: str, links: list[str]) -> None:
    body = "\n".join(f"Related: [[{link}]]" for link in links)
    (vault / f"{name}.md").write_text(
        f"---\nid: {name}\ntenant_id: {tenant}\ndomain: platform\nrisk_tier: high\nversion: 0.1\n---\n\n# {name}\n{body}\n",
        encoding="utf-8",
    )


def test_depth_is_limited_to_two_hops(tmp_path):
    _note(tmp_path, "a", "tenant_a", ["b"])
    _note(tmp_path, "b", "tenant_a", ["c"])
    _note(tmp_path, "c", "tenant_a", ["d"])
    _note(tmp_path, "d", "tenant_a", [])
    graph = build_subgraph(tmp_path, "tenant_a", "a", 2)
    ids = {node["id"] for node in graph["nodes"]}
    assert ids == {"a", "b", "c"}
    assert {"source": "b", "target": "c"} in graph["edges"]


def test_other_tenant_notes_are_never_returned(tmp_path):
    _note(tmp_path, "a", "tenant_a", ["secret"])
    _note(tmp_path, "secret", "tenant_b", [])
    graph = build_subgraph(tmp_path, "tenant_a", "a", 2)
    assert {node["id"] for node in graph["nodes"]} == {"a"}
    assert graph["edges"] == []


def test_note_without_tenant_is_not_visible(tmp_path):
    (tmp_path / "untagged.md").write_text("---\nid: untagged\n---\n# untagged\n", encoding="utf-8")
    graph = build_subgraph(tmp_path, "tenant_a", "untagged", 2)
    assert graph["nodes"] == []


def test_unknown_anchor_returns_empty_subgraph(tmp_path):
    _note(tmp_path, "a", "tenant_a", [])
    graph = build_subgraph(tmp_path, "tenant_a", "missing", 2)
    assert graph["nodes"] == [] and graph["edges"] == []


def test_repo_vault_note_is_visible_only_to_its_tenant():
    from app.mcp_servers.graphify_server import VAULT_DIR
    visible = build_subgraph(VAULT_DIR, "tenant_demo", "enterprise-agent-core", 2)
    assert [node["id"] for node in visible["nodes"]] == ["enterprise-agent-core"]
    hidden = build_subgraph(VAULT_DIR, "tenant_other", "enterprise-agent-core", 2)
    assert hidden["nodes"] == []
