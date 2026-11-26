"""Unit tests covering models, safety policy, JSON-RPC framing, tree pruning, and MockBackend."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from a11ypilot.backends import (
    DesktopBackend,
    ElementVerificationError,
    MockBackend,
    WindowNotFoundError,
    prune_and_index_tree,
)
from a11ypilot.models import (
    REDACTED_PASSWORD,
    A11yNode,
    A11yRole,
    ActionRequest,
    ActionStatus,
    ActionType,
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    ElementLocator,
    ExecutionMode,
    JsonRpcNotification,
    JsonRpcRequest,
    JsonRpcResponse,
    MacroPlaybook,
    MacroStep,
    MCPTool,
    Rect,
    RiskAssessment,
    RiskLevel,
    SafetyPolicy,
    WindowInfo,
    is_notification,
    load_policy,
    make_error_response,
    parse_jsonrpc_frame,
)


def test_rect_center_and_normalization() -> None:
    window_rect = Rect(x=100, y=50, width=1000, height=500)
    rect = Rect(x=200, y=150, width=200, height=100)
    assert rect.center == (300, 200)

    normalized = rect.with_normalized(window_rect)
    assert normalized.rel_x == pytest.approx(0.1)
    assert normalized.rel_y == pytest.approx(0.2)
    assert normalized.rel_w == pytest.approx(0.2)
    assert normalized.rel_h == pytest.approx(0.2)

    out_of_bounds = Rect(x=-50, y=900, width=5000, height=2000).with_normalized(window_rect)
    assert 0.0 <= out_of_bounds.rel_x <= 1.0
    assert 0.0 <= out_of_bounds.rel_y <= 1.0
    assert out_of_bounds.rel_x == 0.0
    assert out_of_bounds.rel_y == 1.0
    assert out_of_bounds.rel_w == 1.0
    assert out_of_bounds.rel_h == 1.0

    zero_window = Rect(x=0, y=0, width=0, height=-10)
    safe = rect.with_normalized(zero_window)
    assert (safe.rel_x, safe.rel_y, safe.rel_w, safe.rel_h) == (0.0, 0.0, 0.0, 0.0)


@pytest.mark.parametrize(
    ("role", "name", "automation_id", "is_password", "raw_value"),
    [
        (A11yRole.PASSWORD, "Login", None, False, "hunter2"),
        (A11yRole.PASSWORD, "PIN", None, False, None),
        (A11yRole.TEXT_INPUT, "Account Password", None, False, "s3cr3t"),
        (A11yRole.TEXT_INPUT, "One-Time Passcode", None, False, "994411"),
        (A11yRole.TEXT_INPUT, "API Secret", None, False, "sk_live_abc"),
        (A11yRole.TEXT_INPUT, "Signing", "secret_key_input", False, "key-123"),
        (A11yRole.TEXT_INPUT, "Key", "private key field", False, "pem-body"),
        (A11yRole.TEXT_INPUT, "OAuth", "client_secret", False, "cs-999"),
        (A11yRole.TEXT_INPUT, "Bearer", "Access Token", False, "tok-xyz"),
        (A11yRole.TEXT_INPUT, "Custom Field", "fld_custom", True, "raw-val"),
    ],
)
def test_a11y_node_password_redaction_defense_in_depth(
    role: A11yRole,
    name: str,
    automation_id: str | None,
    is_password: bool,
    raw_value: str | None,
) -> None:
    node = A11yNode(
        role=role,
        name=name,
        automation_id=automation_id,
        is_password=is_password,
        value=raw_value,
        bounds=Rect(x=0, y=0, width=120, height=30),
    )
    assert node.is_password is True
    assert node.value == REDACTED_PASSWORD


def test_non_input_label_with_secret_name_is_not_redacted() -> None:
    label = A11yNode(
        role=A11yRole.TEXT,
        name="API Secret",
        value="Enter your API Secret below",
        bounds=Rect(x=0, y=0, width=150, height=24),
    )
    assert label.is_password is False
    assert label.value == "Enter your API Secret below"


def test_element_locator_is_frozen() -> None:
    locator = ElementLocator(
        snapshot_id="snap-1",
        ref="@e1",
        window_id="win-1",
        window_title="App",
        process_name="app.exe",
        role=A11yRole.BUTTON,
        name="Save",
        bounds=Rect(x=10, y=10, width=80, height=30),
    )
    with pytest.raises(ValidationError):
        locator.name = "Mutated"  # type: ignore[misc]


def test_actions_and_macro_playbook_models() -> None:
    req = ActionRequest(
        window_id="win-1",
        action=ActionType.HOTKEY,
        keys="Ctrl + Shift + S",  # type: ignore[arg-type]
    )
    assert req.keys == ["Ctrl", "Shift", "S"]

    step_ref = MacroStep(action=ActionType.CLICK, ref="@e2")
    assert step_ref.ref == "@e2"

    step_semantic = MacroStep(
        action=ActionType.TYPE,
        target_name="Service Name",
        target_role=A11yRole.TEXT_INPUT,
        target_automation_id="service_name",
        text="payments-gateway",
    )
    assert step_semantic.target_name == "Service Name"

    with pytest.raises(ValidationError):
        MacroStep(action=ActionType.CLICK)

    hotkey_step = MacroStep(action=ActionType.HOTKEY, keys=["Ctrl", "S"])
    playbook = MacroPlaybook(
        name="Test Macro",
        window_query="CloudOps",
        steps=[step_ref, step_semantic, hotkey_step],
    )
    assert len(playbook.steps) == 3
    assert ActionStatus.DRY_RUN == "dry_run"


def test_safety_policy_and_packaged_yaml_parity(
    default_policy: SafetyPolicy,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    root_yaml = repo_root / "config" / "default-policy.yaml"
    packaged_yaml = repo_root / "src" / "a11ypilot" / "config" / "default-policy.yaml"

    assert root_yaml.read_bytes() == packaged_yaml.read_bytes()
    assert default_policy == load_policy(root_yaml)

    # Ensure packaged policy loads independently of current working directory.
    monkeypatch.chdir(tmp_path)
    assert load_policy() == default_policy
    assert default_policy.mode == ExecutionMode.SAFE
    assert default_policy.is_terminal_process("powershell.exe") is True
    assert default_policy.is_terminal_process("WindowsTerminal") is True
    assert default_policy.is_terminal_process("cloudops-console.exe") is False
    assert default_policy.is_dangerous_hotkey("Ctrl + Alt + Del") is True
    assert default_policy.is_dangerous_hotkey(["Alt", "F4"]) is True
    assert default_policy.is_dangerous_hotkey("Ctrl+S") is False

    crit_patterns = default_policy.compiled_critical_patterns()
    assert any(p.search("Delete Production Cluster") for p in crit_patterns)
    assert any(p.search("Wipe Staging Database") for p in crit_patterns)
    assert not any(p.search("Replay Macro") for p in crit_patterns)
    assert not any(p.search("Dropdown Menu") for p in crit_patterns)

    high_patterns = default_policy.compiled_high_risk_patterns()
    assert not any(p.search("Deploy to Staging") for p in high_patterns)
    assert any(p.search("Publish Release") for p in high_patterns)
    assert any(p.search("Revoke Active Tokens") for p in high_patterns)

    assessment = RiskAssessment(
        level=RiskLevel.CRITICAL,
        reasons=["Matches critical pattern: delete"],
        requires_approval=True,
        blocked=False,
        mode=ExecutionMode.SAFE,
    )
    assert assessment.level.rank == 3

    apr = ApprovalRequest(
        window_id="win-1",
        action="click",
        target_name="Delete Production Cluster",
        target_role="button",
        risk_level=RiskLevel.CRITICAL,
    )
    assert apr.status == ApprovalStatus.PENDING

    decision = ApprovalDecision(decision="approve")
    assert decision.approved is True


def test_jsonrpc_models_and_bool_id_rejection() -> None:
    req = JsonRpcRequest(id=1, method="tools/list")
    assert req.id == 1

    req_str = JsonRpcRequest(id="abc", method="tools/call", params={"name": "snapshot"})
    assert req_str.id == "abc"

    for bad_id in (True, False):
        with pytest.raises(ValidationError):
            JsonRpcRequest(id=bad_id, method="tools/list")
        with pytest.raises(ValidationError):
            JsonRpcResponse(id=bad_id, result={})
        with pytest.raises(ValueError, match="boolean"):
            make_error_response(bad_id, -32600, "Invalid Request")

    notif = JsonRpcNotification(method="notifications/initialized")
    assert notif.method == "notifications/initialized"
    assert is_notification({"jsonrpc": "2.0", "method": "ping"}) is True
    assert is_notification({"jsonrpc": "2.0", "id": 1, "method": "ping"}) is False

    tool = MCPTool(
        name="a11y_snapshot", description="Capture snapshot", inputSchema={"type": "object"}
    )
    assert tool.name == "a11y_snapshot"

    assert parse_jsonrpc_frame('{"jsonrpc": "2.0", "id": 1, "method": "ping"}')["method"] == "ping"
    batch = parse_jsonrpc_frame(b'[{"jsonrpc": "2.0", "id": 1, "method": "a"}]')
    assert isinstance(batch, list) and len(batch) == 1

    for bad_frame in (b"\xff\xfe", "", "[]", "[1]", "42", "{not-json"):
        with pytest.raises(ValueError):
            parse_jsonrpc_frame(bad_frame)


def test_prune_and_index_tree_noise_flattening_and_caps(sample_window: WindowInfo) -> None:
    raw = A11yNode(
        role=A11yRole.WINDOW,
        name="Test Window",
        runtime_id=(1, 0),
        bounds=sample_window.bounds,
        children=[
            A11yNode(
                role=A11yRole.PANE,
                name="",
                bounds=Rect(x=100, y=50, width=900, height=400),
                children=[
                    A11yNode(
                        role=A11yRole.PANE,
                        name="",
                        bounds=Rect(x=100, y=50, width=900, height=400),
                        children=[
                            A11yNode(
                                role=A11yRole.BUTTON,
                                name="Submit",
                                runtime_id=(1, 1),
                                bounds=Rect(x=200, y=100, width=100, height=40),
                                supported_actions=["click"],
                            ),
                            A11yNode(
                                role=A11yRole.PASSWORD,
                                name="Token",
                                value="top-secret-value",
                                runtime_id=(1, 2),
                                bounds=Rect(x=200, y=160, width=200, height=30),
                            ),
                        ],
                    )
                ],
            ),
            A11yNode(
                role=A11yRole.BUTTON,
                name="Hidden Button",
                visible=False,
                runtime_id=(1, 3),
                bounds=Rect(x=200, y=200, width=100, height=30),
            ),
            A11yNode(
                role=A11yRole.BUTTON,
                name="Offscreen Button",
                offscreen=True,
                runtime_id=(1, 4),
                bounds=Rect(x=200, y=240, width=100, height=30),
            ),
            A11yNode(
                role=A11yRole.BUTTON,
                name="Zero Area",
                runtime_id=(1, 5),
                bounds=Rect(x=200, y=280, width=0, height=30),
            ),
        ],
    )

    snapshot = prune_and_index_tree(raw, sample_window, snapshot_id="snap-prune-1")
    assert snapshot.truncated is False
    assert [child.name for child in snapshot.root.children] == ["Submit", "Token"]
    assert list(snapshot.elements.keys()) == ["@e1", "@e2"]
    assert snapshot.telemetry.total_raw_nodes == 8
    assert snapshot.telemetry.pruned_nodes == 3
    assert snapshot.telemetry.interactive_count == 2
    assert snapshot.telemetry.tokens_saved > 0
    assert snapshot.telemetry.savings_percent > 0.0

    token_node = snapshot.find_node_by_ref("@e2")
    assert token_node is not None
    assert token_node.value == REDACTED_PASSWORD
    assert "top-secret-value" not in snapshot.to_compact_text()
    assert REDACTED_PASSWORD in snapshot.to_compact_text()
    assert snapshot.find_node_by_ref("@e99") is None

    # Depth cap
    deep = A11yNode(
        role=A11yRole.BUTTON,
        name="Leaf",
        bounds=Rect(x=110, y=60, width=50, height=20),
    )
    for idx in range(5):
        deep = A11yNode(
            role=A11yRole.TOOLBAR,
            name=f"Level {idx}",
            bounds=Rect(x=100, y=50, width=500, height=200),
            children=[deep],
        )
    deep_root = A11yNode(
        role=A11yRole.WINDOW,
        name="Deep",
        bounds=sample_window.bounds,
        children=[deep],
    )
    depth_capped = prune_and_index_tree(deep_root, sample_window, snapshot_id="snap-d", max_depth=2)
    assert depth_capped.truncated is True
    assert depth_capped.truncation_reason == "max_depth"

    # Node cap
    many_buttons = [
        A11yNode(
            role=A11yRole.BUTTON,
            name=f"Btn {i}",
            runtime_id=(2, i),
            bounds=Rect(x=110, y=60 + i * 10, width=80, height=20),
        )
        for i in range(10)
    ]
    wide_root = A11yNode(
        role=A11yRole.WINDOW,
        name="Wide",
        bounds=sample_window.bounds,
        children=many_buttons,
    )
    node_capped = prune_and_index_tree(wide_root, sample_window, snapshot_id="snap-n", max_nodes=4)
    assert node_capped.truncated is True
    assert node_capped.truncation_reason == "max_nodes"
    assert node_capped.telemetry.pruned_nodes <= 4

    # Timeout cap
    timed_out = prune_and_index_tree(
        wide_root, sample_window, snapshot_id="snap-t", timeout_seconds=0.0
    )
    assert timed_out.truncated is True
    assert timed_out.truncation_reason == "timeout"


def test_prune_cycle_detection_object_and_runtime_id(sample_window: WindowInfo) -> None:
    child = A11yNode(
        role=A11yRole.TOOLBAR,
        name="CyclicToolbar",
        runtime_id=(9, 1),
        bounds=Rect(x=110, y=60, width=200, height=40),
    )
    root = A11yNode(
        role=A11yRole.WINDOW,
        name="Cycle Window",
        runtime_id=(9, 0),
        bounds=sample_window.bounds,
        children=[child],
    )
    child.children.append(root)  # Direct Python object cycle

    dup_runtime = A11yNode(
        role=A11yRole.BUTTON,
        name="Duplicate RuntimeID",
        runtime_id=(9, 1),
        bounds=Rect(x=120, y=70, width=80, height=30),
    )
    child.children.append(dup_runtime)

    snap = prune_and_index_tree(root, sample_window, snapshot_id="snap-cycle")
    assert snap.telemetry.pruned_nodes == 2
    assert len(snap.root.children) == 1


async def test_mock_backend_stateful_workflow_and_stale_ref_detection(
    mock_backend: MockBackend,
) -> None:
    assert isinstance(mock_backend, DesktopBackend)
    assert mock_backend.name == "mock"
    assert mock_backend.is_available() is True

    windows = await mock_backend.list_windows()
    titles = {w.title: w for w in windows}
    assert {"CloudOps Console", "Local Notes"} == set(titles)

    cloudops = titles["CloudOps Console"]
    snap1 = await mock_backend.capture_snapshot(cloudops.window_id)
    compact1 = snap1.to_compact_text()

    assert REDACTED_PASSWORD in compact1
    assert "sk_live_cloudops" not in compact1
    assert "sk_live_cloudops" not in snap1.model_dump_json()
    assert 'val="billing-api"' in compact1
    assert 'val="v2.4.1"' in compact1
    assert 'val="staging"' in compact1

    by_name = {loc.name: loc for loc in snap1.elements.values()}
    assert {
        "Deployments",
        "Secrets",
        "Danger Zone",
        "Service Name",
        "Version Tag",
        "API Secret",
        "Environment",
        "Enable Canary Rollout",
        "Run Smoke Tests",
        "Deploy to Staging",
        "Delete Production Cluster",
    }.issubset(by_name)

    assert await mock_backend.verify_element(by_name["Deploy to Staging"]) is True

    # Mutate Service Name, toggle Canary, select Environment, and Deploy
    res_type = await mock_backend.perform_action(
        ActionRequest(
            window_id=cloudops.window_id,
            snapshot_id=snap1.snapshot_id,
            ref=by_name["Service Name"].ref,
            action=ActionType.TYPE,
            text="payments-gateway",
            clear_first=True,
        )
    )
    assert res_type.status == ActionStatus.EXECUTED

    res_toggle = await mock_backend.perform_action(
        ActionRequest(
            window_id=cloudops.window_id,
            snapshot_id=snap1.snapshot_id,
            ref=by_name["Enable Canary Rollout"].ref,
            action=ActionType.TOGGLE,
        )
    )
    assert res_toggle.status == ActionStatus.EXECUTED

    res_select = await mock_backend.perform_action(
        ActionRequest(
            window_id=cloudops.window_id,
            snapshot_id=snap1.snapshot_id,
            ref=by_name["Environment"].ref,
            action=ActionType.SELECT,
            option="production",
        )
    )
    assert res_select.status == ActionStatus.EXECUTED

    res_deploy = await mock_backend.perform_action(
        ActionRequest(
            window_id=cloudops.window_id,
            snapshot_id=snap1.snapshot_id,
            ref=by_name["Deploy to Staging"].ref,
            action=ActionType.CLICK,
        )
    )
    assert res_deploy.status == ActionStatus.EXECUTED
    assert "payments-gateway" in res_deploy.message
    assert "production" in res_deploy.message

    # Switch to Secrets tab -> stale ref from Deployments tab must now fail verification!
    deploy_btn_locator = by_name["Deploy to Staging"]
    res_tab = await mock_backend.perform_action(
        ActionRequest(
            window_id=cloudops.window_id,
            snapshot_id=snap1.snapshot_id,
            ref=by_name["Secrets"].ref,
            action=ActionType.CLICK,
        )
    )
    assert res_tab.status == ActionStatus.EXECUTED
    assert await mock_backend.verify_element(deploy_btn_locator) is False

    with pytest.raises(ElementVerificationError):
        await mock_backend.perform_action(
            ActionRequest(
                window_id=cloudops.window_id,
                snapshot_id=snap1.snapshot_id,
                ref=deploy_btn_locator.ref,
                action=ActionType.CLICK,
            )
        )

    snap_secrets = await mock_backend.capture_snapshot(cloudops.window_id)
    assert "Webhook Signing Secret" in {loc.name for loc in snap_secrets.elements.values()}
    assert "sk_live_cloudops" not in snap_secrets.model_dump_json()

    # Local Notes window check
    notes = titles["Local Notes"]
    snap_notes = await mock_backend.capture_snapshot(notes.window_id)
    notes_by_name = {loc.name: loc for loc in snap_notes.elements.values()}
    assert {"Note Title", "Editor", "Save Note"}.issubset(notes_by_name)

    save_res = await mock_backend.perform_action(
        ActionRequest(
            window_id=notes.window_id,
            snapshot_id=snap_notes.snapshot_id,
            ref=notes_by_name["Save Note"].ref,
            action=ActionType.CLICK,
        )
    )
    assert save_res.status == ActionStatus.EXECUTED

    with pytest.raises(WindowNotFoundError):
        await mock_backend.capture_snapshot("win-does-not-exist")

    await mock_backend.close()
    assert mock_backend.is_available() is False
