"""Polished cloud-first BugHunter AI operations workspace.

The desktop is a client only: all project state and hunt results are loaded
from the authenticated central API. The persistent worker is independent.
"""
from pathlib import Path

from PySide6.QtCore import Qt, QTimer, QSettings
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QLineEdit,
    QPushButton, QListWidget, QGroupBox, QFrame, QTextEdit, QTabWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QProgressBar, QListWidgetItem,
    QComboBox, QMessageBox, QFileDialog,
)


class CloudWorkspace(QWidget):
    """Single cloud workspace for projects, scope, hunts and evidence."""

    def __init__(self, window):
        super().__init__(window)
        self.host_window = window
        self.client = window.api_client
        self._refreshing = False
        self._settings = QSettings("BugHunterAI", "BugHunterAI")
        self._build()
        self.timer = QTimer(self)
        self.timer.setInterval(10000)
        self.timer.timeout.connect(self.refresh_workspace)
        self.timer.start()

    def _build(self):
        self.setObjectName("cloudWorkspace")
        self.setStyleSheet("""
          QWidget#cloudWorkspace { background:#0a1020; color:#e7eef9; }
          QGroupBox { background:#101b2e; border:1px solid #243852;
            border-radius:12px; margin-top:12px; padding:12px; font-weight:700; }
          QGroupBox::title { subcontrol-origin:margin; left:14px;
            padding:0 7px; color:#a9bfdc; }
          QPushButton { background:#1677df; border:0; border-radius:7px;
            padding:10px 15px; color:#fff; font-weight:700; }
          QPushButton:hover { background:#258cf4; }
          QPushButton:disabled { background:#26364d; color:#71839b; }
          QLineEdit, QTextEdit, QListWidget, QTableWidget {
            background:#0c1728; color:#e7eef9; border:1px solid #263b57;
            border-radius:7px; padding:7px; selection-background-color:#185ca4; }
          QTabWidget::pane { border:1px solid #243852; border-radius:9px;
            background:#0f1a2c; }
          QTabBar::tab { background:#15243a; color:#9eb3ce; padding:11px 16px;
            margin-right:3px; border-top-left-radius:7px; border-top-right-radius:7px; }
          QTabBar::tab:selected { background:#1b3b60; color:#fff; }
          QHeaderView::section { background:#182a42; color:#b9cce3; border:0;
            border-bottom:1px solid #304965; padding:9px; font-weight:700; }
          QTableWidget { gridline-color:#1d3048; alternate-background-color:#101e32; }
        """)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(22, 18, 22, 14)
        outer.setSpacing(14)

        header = QHBoxLayout()
        brand = QVBoxLayout()
        title = QLabel("BUGHUNTER AI")
        title.setStyleSheet("font-size:25px;font-weight:900;letter-spacing:1.5px;color:#55b8ff")
        subtitle = QLabel("AUTHORIZED SECURITY RESEARCH · CLOUD OPERATIONS")
        subtitle.setStyleSheet("font-size:10px;font-weight:700;letter-spacing:1.6px;color:#8ea6c4")
        brand.addWidget(title)
        brand.addWidget(subtitle)
        header.addLayout(brand)
        header.addStretch(1)
        connected = QLabel("●  CLOUD CONNECTED")
        connected.setStyleSheet("color:#62d6a4;font-weight:800;padding:8px 12px;background:#102b2a;border-radius:7px")
        header.addWidget(connected)
        account = QLabel(f"ACCOUNT  {self.host_window.remote_account.get('username', 'Account')}")
        account.setStyleSheet("color:#b6c8df;padding:8px")
        header.addWidget(account)
        refresh = QPushButton("↻  Refresh")
        refresh.setStyleSheet("background:#263b58")
        refresh.clicked.connect(self.refresh_projects)
        header.addWidget(refresh)
        logout = QPushButton("Log out")
        logout.setStyleSheet("background:#3a485c")
        logout.clicked.connect(self.host_window.remote_logout)
        header.addWidget(logout)
        outer.addLayout(header)

        create_box = QGroupBox("NEW PROGRAMME PROJECT")
        create_grid = QGridLayout(create_box)
        self.remote_project_name = QLineEdit()
        self.remote_project_name.setPlaceholderText("Project name — e.g. Example Bug Bounty")
        self.remote_project_url = QLineEdit()
        self.remote_project_url.setPlaceholderText("Official programme URL (https://...)")
        create_grid.addWidget(QLabel("Project name"), 0, 0)
        create_grid.addWidget(QLabel("Programme URL"), 0, 1)
        create_grid.addWidget(self.remote_project_name, 1, 0)
        create_grid.addWidget(self.remote_project_url, 1, 1)
        create = QPushButton("＋  CREATE PROJECT")
        create.setMinimumHeight(42)
        create.clicked.connect(self.host_window.new_remote_project)
        create_grid.addWidget(create, 1, 2)
        self.remote_create_project_button = create
        self.remote_analyze_button = QPushButton("ANALYZE PROJECT  →")
        self.remote_analyze_button.setMinimumHeight(42)
        self.remote_analyze_button.setStyleSheet("background:#0d8b70")
        self.remote_analyze_button.setEnabled(False)
        self.remote_analyze_button.clicked.connect(self.host_window.analyze_remote_program)
        create_grid.addWidget(self.remote_analyze_button, 1, 3)
        create_grid.setColumnStretch(0, 1)
        create_grid.setColumnStretch(1, 2)
        outer.addWidget(create_box)

        # Keep history widgets for compatibility, but do not expose them as navigation.
        body = QHBoxLayout()
        self.remote_project_list = QListWidget(self)
        self.remote_archived_list = QListWidget(self)
        self.remote_project_list.itemClicked.connect(self.host_window.select_remote_project)
        self.remote_archived_list.itemClicked.connect(self.host_window.select_remote_archived_project)

        work = QWidget()
        work_layout = QVBoxLayout(work)
        work_layout.setContentsMargins(0, 0, 0, 0)
        work_layout.setSpacing(10)
        project_header = QHBoxLayout()
        self.remote_selected_project_title = QLabel("Select a project to open its workspace")
        self.remote_selected_project_title.setStyleSheet("font-size:21px;font-weight:800;color:#f1f6ff")
        project_header.addWidget(self.remote_selected_project_title)
        project_header.addStretch(1)
        self.remote_archive_button = QPushButton("Delete project")
        self.remote_archive_button.setStyleSheet("background:#46566d")
        self.remote_archive_button.clicked.connect(self.host_window.archive_remote_project)
        self.remote_archive_button.hide()
        project_header.addWidget(self.remote_archive_button)
        self.remote_restore_button = QPushButton("Restore")
        self.remote_restore_button.setStyleSheet("background:#46566d")
        self.remote_restore_button.clicked.connect(self.host_window.restore_remote_project)
        self.remote_restore_button.hide()
        project_header.addWidget(self.remote_restore_button)
        work_layout.addLayout(project_header)
        self.remote_selected_project_title.hide()

        self.remote_stage_status = QLabel(
            "Create a project with its official programme URL and name, then analyze the programme policy."
        )
        self.remote_stage_status.setWordWrap(True)
        self.remote_stage_status.setStyleSheet(
            "color:#b8cbe2;background:#12243a;border:1px solid #2a4564;"
            "border-radius:9px;padding:12px;font-size:12px"
        )
        work_layout.addWidget(self.remote_stage_status)

        actions = QHBoxLayout()
        self.remote_scope_hint = QLabel(
            "Create a project, review its official policy, then approve the exact authorized assets."
        )
        self.remote_scope_hint.setWordWrap(True)
        self.remote_scope_hint.setStyleSheet(
            "color:#f0c66b;background:#25251d;border:1px solid #5b4a28;"
            "border-radius:7px;padding:10px"
        )
        actions.addWidget(self.remote_scope_hint, 1)
        self.remote_scope_hint.hide()
        policy = QPushButton("POLICY & SCOPE")
        policy.setStyleSheet("background:#31577e")
        policy.setMinimumHeight(42)
        policy.clicked.connect(self.host_window.open_remote_project_tools)
        policy.hide()
        actions.addWidget(policy)
        self.remote_start_hunt_button = QPushButton("▶  START HUNT")
        self.remote_start_hunt_button.setStyleSheet("background:#087f5b;font-size:14px")
        self.remote_start_hunt_button.setMinimumHeight(42)
        self.remote_start_hunt_button.setEnabled(False)
        self.remote_start_hunt_button.hide()
        self.remote_start_hunt_button.clicked.connect(self.host_window.start_remote_hunt)
        actions.addWidget(self.remote_start_hunt_button)

        self.remote_report_format = QComboBox()
        for label, value in (("PDF", "pdf"), ("Word (.docx)", "docx"),
                             ("HTML", "html"), ("Markdown", "markdown"),
                             ("JSON", "json")):
            self.remote_report_format.addItem(label, value)
        self.remote_download_report_button = QPushButton("DOWNLOAD REPORT")
        self.remote_download_report_button.setStyleSheet("background:#0d8b70")
        self.remote_download_report_button.clicked.connect(self.host_window.download_remote_report)
        self.remote_report_format.hide()
        self.remote_download_report_button.hide()
        actions.addWidget(self.remote_report_format)
        actions.addWidget(self.remote_download_report_button)
        work_layout.addLayout(actions)

        self.remote_workspace_tabs = QTabWidget()
        work_layout.addWidget(self.remote_workspace_tabs, 1)
        self.remote_workspace_tabs.hide()
        self._build_overview()
        self.remote_assets_table = self._make_table(
            ["Host", "Scope decision", "Authorization", "Policy / review notes"]
        )
        self.remote_endpoints_table = self._make_table(
            ["Method", "Endpoint", "Type", "Notes"]
        )
        self._build_assessments()
        self.remote_findings_table = self._make_table(
            ["Severity", "Confidence", "Status", "Category", "Finding", "Affected asset", "Evidence"]
        )
        self.remote_workspace_tabs.addTab(self.remote_findings_table, "Vulnerabilities")
        self.remote_jobs_table = self._make_table(
            ["Job", "Status", "Progress", "Last checkpoint", "Created", "Finished / error"]
        )
        self.remote_evidence_table = self._make_table(
            ["ID", "Evidence file", "SHA-256", "Size", "Linked record", "Added"]
        )
        self.remote_workspace_tabs.addTab(self.remote_evidence_table, "Evidence")
        self.remote_activity_table = self._make_table(["Time", "Event", "Details"])
        body.addWidget(work, 1)
        outer.addLayout(body, 1)

        footer = QLabel(
            "Independent cloud worker · Exact human-approved scope · "
            "Discovered assets remain candidates · Evidence retained centrally"
        )
        footer.setStyleSheet("color:#7188a6;font-size:10px;padding:2px")
        outer.addWidget(footer)

    def _build_overview(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(12)
        metrics = QGridLayout()
        metrics.setSpacing(10)
        self.remote_metric_values = {}
        specs = [
            ("Approved assets", "approved_assets", "Explicitly authorized hosts"),
            ("Candidates", "candidates", "Review in Policy & Scope"),
            ("Endpoints", "endpoints", "Discovered URLs and API routes"),
            ("Findings", "findings", "Potential findings for review"),
            ("Active hunts", "active_hunts", "Queued or running jobs"),
            ("Evidence records", "evidence", "Stored evidence references"),
        ]
        for index, (label, key, caption) in enumerate(specs):
            card = QFrame()
            card.setStyleSheet(
                "QFrame{background:#13243a;border:1px solid #29425f;border-radius:10px}"
            )
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(14, 12, 14, 12)
            heading = QLabel(label.upper())
            heading.setStyleSheet(
                "color:#91a9c7;font-size:10px;font-weight:800;letter-spacing:1px"
            )
            value = QLabel("—")
            value.setStyleSheet("color:#60baff;font-size:27px;font-weight:900")
            desc = QLabel(caption)
            desc.setStyleSheet("color:#8298b5;font-size:10px")
            card_layout.addWidget(heading)
            card_layout.addWidget(value)
            card_layout.addWidget(desc)
            self.remote_metric_values[key] = value
            metrics.addWidget(card, index // 3, index % 3)
        layout.addLayout(metrics)
        self.remote_project_details = QTextEdit()
        self.remote_project_details.setReadOnly(True)
        self.remote_project_details.setMaximumHeight(115)
        self.remote_project_details.setPlaceholderText(
            "Select a project to view its programme and scope status."
        )
        layout.addWidget(self.remote_project_details)
        latest = QGroupBox("LATEST HUNT")
        latest_layout = QVBoxLayout(latest)
        self.remote_hunt_status = QLabel("No hunt has been queued.")
        self.remote_hunt_status.setStyleSheet("color:#b9cbe1;font-weight:700")
        latest_layout.addWidget(self.remote_hunt_status)
        self.remote_hunt_progress = QProgressBar()
        self.remote_hunt_progress.setRange(0, 100)
        self.remote_hunt_progress.setValue(0)
        self.remote_hunt_progress.setStyleSheet(
            "QProgressBar{background:#0b1728;border:1px solid #2b415e;"
            "border-radius:6px;height:18px;text-align:center;color:#fff}"
            "QProgressBar::chunk{background:#1684df;border-radius:5px}"
        )
        latest_layout.addWidget(self.remote_hunt_progress)
        layout.addWidget(latest)
        layout.addStretch(1)
        self.remote_workspace_tabs.addTab(page, "Progress")

    def _build_assessments(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        note = QLabel(
            "Guided vulnerability-category coverage and recorded observations. "
            "A completed check is not proof that an application is secure."
        )
        note.setWordWrap(True)
        note.setStyleSheet("color:#91a9c7;padding:4px")
        layout.addWidget(note)
        self.remote_assessment_table = self._make_table(
            ["Vulnerability category", "Checks recorded", "Completed",
             "Skipped", "Failed", "Latest outcome"]
        )
        layout.addWidget(self.remote_assessment_table, 1)
        layout.addWidget(QLabel("Guided manual validation plan"))
        self.remote_test_plan_table = self._make_table(
            ["Category", "Assessment", "Status", "Target", "Notes"]
        )
        layout.addWidget(self.remote_test_plan_table, 1)
        layout.addWidget(QLabel("Recorded assessment observations"))
        self.remote_checks_table = self._make_table(
            ["Asset", "Assessment check", "Outcome", "Observed at"]
        )
        layout.addWidget(self.remote_checks_table, 2)

    def _make_table(self, headers):
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setSelectionMode(QTableWidget.SingleSelection)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.setAlternatingRowColors(True)
        table.setWordWrap(False)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        table.horizontalHeader().setStretchLastSection(True)
        table.setSortingEnabled(False)
        return table

    @staticmethod
    def _fill_table(table, rows):
        table.setUpdatesEnabled(False)
        table.setRowCount(0)
        for values in rows[:1500]:
            row = table.rowCount()
            table.insertRow(row)
            for column, value in enumerate(values):
                rendered = str(value if value not in (None, "") else "—")
                item = QTableWidgetItem(rendered)
                item.setToolTip(rendered)
                table.setItem(row, column, item)
        table.setUpdatesEnabled(True)

    def refresh_projects(self):
        if not self.client or not self.client.authenticated:
            return
        try:
            projects = self.client.list_projects()
            if not isinstance(projects, list):
                raise RuntimeError("The API returned an invalid project list.")
            selected_id = self.host_window.remote_project_id
            self.remote_project_list.clear()
            self.remote_archived_list.clear()
            selected_item = None
            for project in projects:
                project_id = project.get("id")
                name = project.get("name", "Unnamed project")
                status = str(project.get("status", "unknown")).lower()
                item = QListWidgetItem(f"{name}   ·   #{project_id}")
                item.setData(Qt.UserRole, project_id)
                if status == "deleted":
                    item.setText(f"{name}   ·   ARCHIVED")
                    self.remote_archived_list.addItem(item)
                else:
                    self.remote_project_list.addItem(item)
                    if project_id == selected_id:
                        selected_item = item
            if selected_item is not None:
                self.remote_project_list.setCurrentItem(selected_item)
                self.host_window.select_remote_project(selected_item)
            elif selected_id is None:
                active_projects = [p for p in projects if str(p.get("status", "")).lower() != "deleted"]
                if active_projects:
                    item = self.remote_project_list.item(0)
                    if item is not None:
                        self.remote_project_list.setCurrentItem(item)
                        self.host_window.select_remote_project(item)
                else:
                    self.clear_workspace()
                    self.remote_project_list.clearSelection()
                    self.host_window.statusBar().showMessage(
                        "Ready for a new authorized programme project."
                    )
            else:
                self.host_window.remote_project_id = None
                self.host_window.remote_project = None
                self.clear_workspace()
        except Exception as exc:
            self.host_window.statusBar().showMessage(f"Could not refresh projects: {exc}")

    def refresh_workspace(self):
        if self._refreshing or not self.client or not self.client.authenticated:
            return
        project_id = self.host_window.remote_project_id
        if not project_id:
            return
        self._refreshing = True
        try:
            project = self.client.get_project(project_id)
            resources = {}
            for name in (
                "assets", "findings", "endpoints", "checks",
                "test-cases", "jobs", "evidence", "activities",
            ):
                value = self.client.list_project_resource(project_id, name)
                if not isinstance(value, list):
                    raise RuntimeError(f"The API returned invalid {name} data.")
                resources[name] = value

            policies = self.client.list_program_policies(project_id)
            latest_policy = policies[0] if policies and isinstance(policies[0], dict) else {}
            candidates = len(latest_policy.get("assets", []))
            assets = resources["assets"]
            approved = [
                item for item in assets
                if item.get("included") and item.get("approved")
            ]
            findings = resources["findings"]
            endpoints = resources["endpoints"]
            checks = resources["checks"]
            tests = resources["test-cases"]
            jobs = resources["jobs"]
            evidence = resources["evidence"]
            activities = resources["activities"]
            active_jobs = [
                job for job in jobs if job.get("status") in {"queued", "running", "paused"}
            ]

            metrics = {
                "approved_assets": len(approved),
                "candidates": candidates,
                "endpoints": len(endpoints),
                "findings": len(findings),
                "active_hunts": len(active_jobs),
                "evidence": len(evidence),
            }
            for key, value in metrics.items():
                self.remote_metric_values[key].setText(str(value))

            self.host_window.remote_project = project
            self.remote_selected_project_title.show()
            self.remote_stage_status.show()
            self.remote_selected_project_title.setText(
                project.get("name", "Selected project")
            )
            self.remote_project_details.setPlainText(
                f"PROJECT #{project.get('id')}   ·   STATUS: "
                f"{str(project.get('status', 'unknown')).upper()}   ·   "
                f"SCOPE: {'APPROVED' if project.get('scope_approved') else 'NOT APPROVED'}\n"
                f"PROGRAMME: {project.get('programme_url') or 'Not supplied'}\n"
                f"APPROVED ASSETS: {len(approved)}   ·   OTHER SCOPE RECORDS: "
                f"{len(assets) - len(approved)}   ·   ENDPOINTS: {len(endpoints)}   ·   "
                f"FINDINGS: {len(findings)}"
            )
            ready = bool(project.get("scope_approved") and approved)
            if ready:
                self.remote_scope_hint.setText(
                    f"Scope approved for {len(approved)} included asset(s). "
                    "Policy-aware assessment is ready. Newly discovered hosts remain "
                    "unapproved until reviewed and separately approved."
                )
                self.remote_scope_hint.setStyleSheet(
                    "color:#7fe0b0;background:#102b28;border:1px solid #285c4b;"
                    "border-radius:7px;padding:10px"
                )
            else:
                self.remote_scope_hint.setText(
                    "Scope is not ready. Review the official programme policy, "
                    "reject exclusions, accept eligible candidates, then approve "
                    "the exact included assets."
                )
                self.remote_scope_hint.setStyleSheet(
                    "color:#f0c66b;background:#25251d;border:1px solid #5b4a28;"
                    "border-radius:7px;padding:10px"
                )

            self._fill_table(self.remote_assets_table, [
                (a.get("host"), "INCLUDED" if a.get("included") else "EXCLUDED",
                 "APPROVED" if a.get("approved") else "NOT APPROVED", a.get("notes"))
                for a in assets
            ])
            self._fill_table(self.remote_endpoints_table, [
                (e.get("method"), e.get("url"), e.get("endpoint_type"), e.get("notes"))
                for e in endpoints
            ])

            def check_category(name):
                value = str(name or "").lower()
                if "cors" in value:
                    return "Cross-origin policy (CORS)"
                if any(term in value for term in ("authorization", "object reference", "cross-account", "role-based")):
                    return "Access control (IDOR / BOLA)"
                if any(term in value for term in ("openapi", "api access", "api operation", "api response", "api disclosure")):
                    return "API security and data exposure"
                if any(term in value for term in ("javascript", "client-side", "source-map")):
                    return "Client-side security"
                if "reflection" in value:
                    return "Reflected input (XSS review)"
                if "redirect" in value:
                    return "Redirect handling"
                if any(term in value for term in ("cookie", "session")):
                    return "Session management"
                if any(term in value for term in ("tls", "transport", "header", "csp", "hsts", "html")):
                    return "Transport and security configuration"
                if any(term in value for term in ("sensitive", "disclosure", "exposure", "secret")):
                    return "Sensitive information exposure"
                if "sql" in value or "database" in value:
                    return "Database error disclosure"
                if "robots" in value or "endpoint" in value:
                    return "Attack-surface discovery"
                return "Web application assessment"

            check_groups = {}
            for check in checks:
                category = check_category(check.get("check_name"))
                bucket = check_groups.setdefault(category, {
                    "completed": 0, "skipped": 0, "failed": 0,
                    "total": 0, "latest": "—",
                })
                outcome = str(check.get("outcome") or "unknown").lower()
                bucket["total"] += 1
                if outcome in {"completed", "passed", "success"}:
                    bucket["completed"] += 1
                elif outcome in {"skipped", "blocked", "not_applicable"}:
                    bucket["skipped"] += 1
                elif outcome in {"failed", "error"}:
                    bucket["failed"] += 1
                if bucket["latest"] == "—":
                    bucket["latest"] = outcome.upper()
            self._fill_table(self.remote_assessment_table, [
                (category, bucket["total"], bucket["completed"],
                 bucket["skipped"], bucket["failed"], bucket["latest"])
                for category, bucket in sorted(check_groups.items())
            ])
            self._fill_table(self.remote_test_plan_table, [
                (test.get("category"), test.get("title"),
                 str(test.get("status", "")).upper(),
                 test.get("target"), test.get("notes"))
                for test in tests
            ])
            self._fill_table(self.remote_checks_table, [
                (c.get("asset"), c.get("check_name"),
                 str(c.get("outcome", "")).upper(), c.get("created_at"))
                for c in checks
            ])
            self._fill_table(self.remote_findings_table, [
                (str(f.get("severity", "")).upper(),
                 str(f.get("confidence", "")).upper(),
                 str(f.get("status", "")).upper(), f.get("category"),
                 f.get("title"), f.get("asset"), f.get("evidence"))
                for f in findings
            ])
            self._fill_table(self.remote_jobs_table, [
                (f"#{j.get('id')} · {j.get('job_type')}",
                 str(j.get("status", "")).upper(),
                 f"{j.get('progress', 0)}%", j.get("checkpoint"),
                 j.get("created_at"), j.get("error_message") or j.get("finished_at"))
                for j in jobs
            ])
            self._fill_table(self.remote_evidence_table, [
                (e.get("id"), e.get("original_name"), e.get("sha256"),
                 f"{e.get('size_bytes', 0)} bytes",
                 f"Finding #{e.get('finding_id')}" if e.get("finding_id")
                 else (f"Test #{e.get('test_case_id')}" if e.get("test_case_id")
                 else (f"Check #{e.get('scan_check_id')}" if e.get("scan_check_id")
                 else "Unlinked")), e.get("created_at"))
                for e in evidence
            ])
            self._fill_table(self.remote_activity_table, [
                (a.get("created_at"), a.get("event"), a.get("details"))
                for a in activities
            ])

            latest = jobs[0] if jobs else None
            if latest:
                self.remote_hunt_status.setText(
                    f"Hunt #{latest.get('id')} · {str(latest.get('status')).upper()} · "
                    f"{latest.get('progress', 0)}% · "
                    f"{latest.get('checkpoint') or 'Waiting for worker'}"
                )
                self.remote_hunt_progress.setValue(
                    max(0, min(100, int(latest.get("progress") or 0)))
                )
            else:
                self.remote_hunt_status.setText("No hunts have been queued for this project.")
                self.remote_hunt_progress.setValue(0)

            archived = str(project.get("status", "")).lower() == "deleted"
            self.remote_archive_button.setEnabled(not archived)
            self.remote_restore_button.setEnabled(archived)
            has_policy = bool(latest_policy)
            self.remote_analyze_button.setEnabled(
                not archived and bool(project.get("programme_url")) and not active_jobs
            )
            self.remote_analyze_button.setText(
                "RE-ANALYZE POLICY" if has_policy else "ANALYZE PROJECT  →"
            )
            self.remote_stage_status.setText(
                f"PROJECT: {project.get('name', 'Selected project')}  ·  "
                + ("STEP 3 — APPROVED SCOPE. Start the hunt when ready." if ready
                   else ("STEP 2 — POLICY SAVED. Review the extracted rules and exact assets, then approve scope." if has_policy
                         else "STEP 2 — Analyze the official programme policy to extract scope, restrictions and testing rules."))
            )
            hunt_jobs = [j for j in jobs if j.get("job_type") == "Automated hunt"]
            self.remote_scope_hint.setVisible(ready)
            self.remote_start_hunt_button.setVisible(
                ready and not archived and (not hunt_jobs or bool(active_jobs))
            )
            self.remote_start_hunt_button.setEnabled(
                ready and not archived and not active_jobs and not hunt_jobs
            )
            self.remote_start_hunt_button.setText(
                f"⏳  HUNT ACTIVE ({len(active_jobs)})" if active_jobs
                else ("HUNT FINISHED" if hunt_jobs else "▶  START HUNT")
            )
            self.remote_workspace_tabs.setVisible(bool(active_jobs) or bool(hunt_jobs) or bool(findings))
            terminal_statuses = {"completed", "failed", "stopped"}
            hunt_finished = bool(hunt_jobs) and all(
                str(j.get("status", "")).lower() in terminal_statuses for j in hunt_jobs
            )
            self.remote_report_format.setVisible(hunt_finished)
            self.remote_download_report_button.setVisible(hunt_finished)
            if hunt_finished:
                latest_hunt_id = max(int(j.get("id", 0)) for j in hunt_jobs)
                notification_key = f"reports/notified/project_{project_id}"
                previously_notified = str(self._settings.value(notification_key, ""))
                failed_marker = f"failed:{latest_hunt_id}"
                report_generation_failed = previously_notified == failed_marker
                if previously_notified not in {str(latest_hunt_id), failed_marker}:
                    failed = sum(str(j.get("status", "")).lower() != "completed" for j in hunt_jobs)
                    try:
                        report_dir = Path.home() / "Downloads"
                        report_dir.mkdir(parents=True, exist_ok=True)
                        safe_name = "".join(
                            char if char.isalnum() or char in "-_" else "_"
                            for char in str(project.get("name") or "bughunter-project")
                        ).strip("_") or "bughunter-project"
                        report_path = report_dir / (
                            f"{safe_name}_hunt_{latest_hunt_id}_security_report.pdf"
                        )
                        report_bytes = self.client.download_report(project_id, "pdf")
                        report_path.write_bytes(report_bytes)
                        self._settings.setValue(notification_key, str(latest_hunt_id))
                        message = (
                            "Hunt finished. I generated your first-person PDF report and saved it to:\n"
                            f"{report_path}\n\n"
                            "You can also choose Word, HTML, Markdown or JSON below."
                        )
                        if failed:
                            message += f"\n\n{failed} job(s) did not complete successfully; the report marks the coverage as partial."
                        QMessageBox.information(self, "Hunt finished — report ready", message)
                    except Exception as report_error:
                        report_generation_failed = True
                        self._settings.setValue(notification_key, failed_marker)
                        self.remote_stage_status.setText(
                            "HUNT FINISHED — automatic PDF generation failed. Use DOWNLOAD REPORT to retry."
                        )
                        QMessageBox.warning(
                            self,
                            "Hunt finished — report needs retry",
                            "The hunt has ended, but the automatic PDF could not be saved. "
                            "Use DOWNLOAD REPORT to generate it again.\n\n"
                            f"{type(report_error).__name__}: {report_error}",
                        )
                if report_generation_failed:
                    self.remote_stage_status.setText(
                        "HUNT FINISHED — automatic PDF generation failed. Use DOWNLOAD REPORT to retry."
                    )
                else:
                    self.remote_stage_status.setText(
                        "HUNT FINISHED — your report is ready to download. "
                        "The report separates confirmed findings, potential leads and incomplete checks."
                    )
            elif active_jobs:
                self.remote_stage_status.setText(
                    "HUNT RUNNING IN THE CLOUD — progress and findings are updating below. "
                    "You can close this desktop; the cloud worker continues independently."
                )
            self.host_window.statusBar().showMessage(
                f"Workspace synced · {len(approved)} approved assets · "
                f"{len(endpoints)} endpoints · {len(findings)} findings"
            )
        except Exception as exc:
            self.host_window.statusBar().showMessage(
                f"Workspace refresh failed: {type(exc).__name__}: {exc}"
            )
        finally:
            self._refreshing = False

    def clear_workspace(self):
        for name in (
            "remote_assets_table", "remote_endpoints_table",
            "remote_assessment_table", "remote_test_plan_table",
            "remote_checks_table", "remote_findings_table", "remote_jobs_table",
            "remote_evidence_table", "remote_activity_table",
        ):
            table = getattr(self, name, None)
            if table is not None:
                table.setRowCount(0)
        for label in self.remote_metric_values.values():
            label.setText("—")
        self.remote_project_details.clear()
        self.remote_hunt_status.setText("Select a project to view hunt activity.")
        self.remote_hunt_progress.setValue(0)
        self.remote_selected_project_title.setText("Select a project to open its workspace")
        self.remote_start_hunt_button.setEnabled(False)
        self.remote_start_hunt_button.hide()
        self.remote_analyze_button.setEnabled(False)
        self.remote_workspace_tabs.hide()
        self.remote_report_format.hide()
        self.remote_download_report_button.hide()
        self.remote_selected_project_title.hide()
        self.remote_stage_status.setText(
            "Create a project with its official programme URL and name, then analyze the programme policy."
        )
