import json
import sys
import subprocess
from pathlib import Path
from PySide6.QtWidgets import QApplication,QMainWindow,QWidget,QVBoxLayout,QHBoxLayout,QLabel,QLineEdit,QPushButton,QMessageBox,QDialog,QTabWidget,QFormLayout,QTextEdit,QListWidget,QListWidgetItem,QInputDialog,QFileDialog,QToolButton,QGroupBox,QGridLayout,QFrame,QHeaderView,QTableWidget,QTableWidgetItem,QCheckBox,QComboBox
from PySide6.QtCore import Qt, QUrl, QTimer
from app.services.passive_recon_worker import PassiveReconWorker
from PySide6.QtWidgets import QProgressBar
from PySide6.QtGui import QDesktopServices
from sqlalchemy import select,func
from app.database.db import SessionLocal,init_db
from app.models.entities import User,Project,Finding,ScanCheck,ScopeAsset,Activity,Endpoint,TestCase,Evidence,AssessmentJob,FindingReview
from app.services.auth import authenticate
from app.services.api_client import APIClient, APIError
from app.ui.cloud_workspace import CloudWorkspace, RemoteAPICallThread, HuntQueueThread
from app.core.config import API_BASE_URL, ENABLE_LOCAL_MODE
from app.services.workflows import add_endpoint,initialize_test_plan,update_test_case,recommend_endpoint_tests
from app.services.evidence import add_evidence,list_evidence,verify_evidence, audit_project_evidence
from app.services.jobs import create_job,create_hunt_job,transition_job,list_jobs,recover_interrupted_jobs,ALLOWED_TRANSITIONS
from app.services.projects import create_project,add_scope_asset,approve_scope,log_activity,delete_project,restore_project
from app.services.analyzer import analyze_programme
from app.services.research import run_safe_assessment
from app.services.analysis_worker import WebsiteAnalysisWorker
from app.services.validation import validate_project_findings
from app.services.reports import export_report
from app.services.coverage import get_project_coverage
from app.services.assessment_records import record_assessment_result, assessment_history
STYLE = "QWidget{background:#0b1220;color:#e5edf8;font-family:Arial;font-size:13px} QLineEdit,QTextEdit,QListWidget{background:#111d30;border:1px solid #263b58;border-radius:6px;padding:8px;color:#e5edf8} QPushButton{background:#087cf0;color:white;border:0;border-radius:6px;padding:9px 14px;font-weight:600} QTabBar::tab{background:#14233a;padding:10px} QTabBar::tab:selected{background:#087cf0}"
class Window(QMainWindow):
 def __init__(self):
  super().__init__()
  self.db = SessionLocal() if ENABLE_LOCAL_MODE else None
  self.user_id=None
  self.project_id=None
  self.analysis_worker=None
  self.passive_recon_worker=None
  self.api_client=None
  self.remote_account=None
  self.remote_project_id=None
  self.remote_project=None
  self.setWindowTitle("BugHunter AI — Personal Security Research")
  self.resize(1080,740)
  self.setStyleSheet(STYLE)
  self._last_hunt_snapshot=None
  self._refreshing_hunt_dashboard=False
  self.job_refresh_timer=QTimer(self)
  self.job_refresh_timer.setInterval(2500)
  self.job_refresh_timer.timeout.connect(self.refresh_evidence_jobs)
  self.job_refresh_timer.start()
  self.show_login()
 def show_login(self):
  self.setWindowTitle("BugHunter AI — Sign in")
  self.setMinimumSize(760,620)
  self.resize(980,700)
  w=QWidget()
  w.setStyleSheet("""
   QWidget { background:#091321; color:#e7eef9; font-family:Arial; }
   QFrame#loginCard { background:#101e31; border:1px solid #29415e; border-radius:18px; }
   QLineEdit { background:#0a1728; border:1px solid #304966; border-radius:8px;
    padding:13px; color:#f2f7ff; font-size:14px; }
   QPushButton { background:#087fdf; border:0; border-radius:8px; padding:13px;
    color:white; font-weight:800; font-size:13px; }
   QPushButton:hover { background:#2495f2; }
  """)
  outer=QVBoxLayout(w)
  outer.setContentsMargins(36,30,36,24)
  outer.addStretch(1)
  card=QFrame()
  card.setObjectName("loginCard")
  card.setMaximumWidth(520)
  layout=QVBoxLayout(card)
  layout.setContentsMargins(36,34,36,30)
  layout.setSpacing(14)
  mark=QLabel("BH")
  mark.setAlignment(Qt.AlignCenter)
  mark.setFixedSize(58,58)
  mark.setStyleSheet("background:#123b61;border:1px solid #286ba3;border-radius:16px;color:#72c8ff;font-size:24px;font-weight:900")
  layout.addWidget(mark,0,Qt.AlignHCenter)
  title=QLabel("BUGHUNTER AI")
  title.setAlignment(Qt.AlignCenter)
  title.setStyleSheet("font-size:27px;font-weight:900;letter-spacing:2px;color:#59baff")
  layout.addWidget(title)
  subtitle=QLabel("AUTHORIZED BUG BOUNTY RESEARCH")
  subtitle.setAlignment(Qt.AlignCenter)
  subtitle.setStyleSheet("font-size:10px;font-weight:800;letter-spacing:2px;color:#91a9c7")
  layout.addWidget(subtitle)
  description=QLabel(
   "Sign in to your secure cloud workspace. Projects, approved scope, "
   "hunt jobs and evidence are shared with the persistent research worker."
  )
  description.setWordWrap(True)
  description.setAlignment(Qt.AlignCenter)
  description.setStyleSheet("color:#a9bdd5;padding:8px 2px 12px")
  layout.addWidget(description)

  self.username=QLineEdit()
  self.username.setPlaceholderText("Username")
  self.username.setClearButtonEnabled(True)
  layout.addWidget(self.username)
  self.password=QLineEdit()
  self.password.setPlaceholderText("Password")
  self.password.setEchoMode(QLineEdit.Password)
  self.password_toggle=QToolButton()
  self.password_toggle.setText("Show")
  self.password_toggle.setCursor(Qt.PointingHandCursor)
  self.password_toggle.setStyleSheet("background:#253a55;border-radius:7px;padding:10px;color:#d9e7f7")
  self.password_toggle.clicked.connect(self.toggle_password_visibility)
  password_row=QHBoxLayout()
  password_row.setSpacing(8)
  password_row.addWidget(self.password,1)
  password_row.addWidget(self.password_toggle)
  layout.addLayout(password_row)

  self.remote_mode_checkbox=None
  if ENABLE_LOCAL_MODE:
   self.remote_mode_checkbox=QCheckBox("Use local developer workspace")
   self.remote_mode_checkbox.setToolTip(
    "Developer-only: use the separate local SQLite workspace instead of cloud."
   )
   self.remote_mode_checkbox.setChecked(False)
   layout.addWidget(self.remote_mode_checkbox)
  else:
   cloud=QLabel(f"●  CLOUD WORKSPACE  ·  {API_BASE_URL}")
   cloud.setAlignment(Qt.AlignCenter)
   cloud.setStyleSheet("color:#6bd7a8;font-size:10px;font-weight:800;padding:9px;background:#102b28;border-radius:7px")
   layout.addWidget(cloud)

  button=QPushButton("SIGN IN  →")
  button.setMinimumHeight(48)
  button.clicked.connect(self.login)
  layout.addWidget(button)
  self.password.returnPressed.connect(self.login)
  footer=QLabel("Your account is authenticated by the central BugHunter AI API.")
  footer.setAlignment(Qt.AlignCenter)
  footer.setStyleSheet("color:#7087a4;font-size:10px;padding-top:5px")
  layout.addWidget(footer)

  outer.addWidget(card,0,Qt.AlignHCenter)
  outer.addStretch(1)
  self.setCentralWidget(w)

 def toggle_password_visibility(self):
  visible = self.password.echoMode() == QLineEdit.Password
  self.password.setEchoMode(QLineEdit.Normal if visible else QLineEdit.Password)
  self.password_toggle.setText("Hide" if visible else "Show")

 def login(self):
  username = self.username.text().strip()
  if self.remote_mode_checkbox is None or not self.remote_mode_checkbox.isChecked():
   self.remote_login(username)
   return
  if not authenticate(self.db, username, self.password.text()):
   QMessageBox.warning(self,"Login","Invalid credentials.")
   return

  user = self.db.scalar(select(User).where(User.username == username))
  if user is None:
   QMessageBox.warning(self,"Login","Account could not be loaded.")
   return

  self.user_id = user.id
  self.db.info["owner_id"] = user.id

  try:
   recover_interrupted_jobs(self.db)
  except Exception as exc:
   self.db.rollback()
   QMessageBox.warning(self,"Job recovery",str(exc))
   return

  self.dashboard()


 # REMOTE_WORKSPACE_V1
 def remote_login(self, username):
  password = self.password.text()
  if not username or not password:
   QMessageBox.warning(self, "Remote login", "Enter your username and password.")
   return

  client = APIClient()
  try:
   client.login(username, password)
   account = client.me()
   if not isinstance(account, dict) or not account.get("id"):
    raise APIError(502, "The API returned an invalid account profile.")

   self.api_client = client
   self.remote_account = account
   self.remote_project_id = None
   self.remote_project = None
   self.password.clear()
   self.remote_dashboard()
  except APIError as exc:
   client.close()
   QMessageBox.warning(self, "Remote login", str(exc))
  except Exception as exc:
   client.close()
   QMessageBox.warning(self, "Remote login", f"Could not open remote workspace: {exc}")

 def remote_dashboard(self):
  if not self.api_client or not self.api_client.authenticated:
   QMessageBox.warning(self, "Remote workspace", "Please log in again.")
   self.show_login()
   return

  self.setWindowTitle("BugHunter AI — Research Operations")
  self.setMinimumSize(1180, 780)
  self.resize(1500, 960)
  self._build_remote_tools_dialog()
  self.cloud_workspace = CloudWorkspace(self)

  # Keep the existing project/policy actions wired to the new workspace.
  for name in (
   "remote_project_name", "remote_project_url", "remote_project_list",
   "remote_archived_list", "remote_selected_project_title",
   "remote_project_details", "remote_scope_hint",
   "remote_start_hunt_button", "remote_archive_button",
   "remote_restore_button", "remote_analyze_button",
   "remote_report_format", "remote_download_report_button",
   "remote_stage_status", "remote_create_project_button",
   "remote_create_project_box", "remote_new_project_button",
   "remote_workspace_tabs", "remote_findings_table",
  ):
   setattr(self, name, getattr(self.cloud_workspace, name))

  self.setCentralWidget(self.cloud_workspace)
  self.statusBar().showMessage("Connected to the central BugHunter AI API.")
  self.refresh_remote_projects()

 def refresh_remote_workspace(self):
  workspace = getattr(self, "cloud_workspace", None)
  if workspace is not None:
   workspace.refresh_workspace()

 def _build_remote_tools_dialog(self):
  dialog = QDialog(self)
  dialog.setWindowTitle("Programme policy, scope & test accounts")
  dialog.setMinimumSize(900, 680)
  dialog.resize(1040, 760)
  outer = QVBoxLayout(dialog)
  intro = QLabel(
   "Review policy evidence and approve only assets explicitly authorized by the programme. "
   "Newly discovered hosts remain unapproved until you review them."
  )
  intro.setWordWrap(True)
  intro.setStyleSheet("color:#b7c8dc;padding:6px")
  outer.addWidget(intro)
  tabs = QTabWidget()
  outer.addWidget(tabs, 1)

  policy_page = QWidget()
  policy_layout = QVBoxLayout(policy_page)
  policy_layout.addWidget(QLabel("Optional policy text for private or inaccessible programmes:"))
  self.remote_policy_text = QTextEdit()
  self.remote_policy_text.setPlaceholderText("Paste official programme policy text here. Leave blank to retrieve the public programme page.")
  self.remote_policy_text.setMaximumHeight(115)
  policy_layout.addWidget(self.remote_policy_text)
  policy_actions = QHBoxLayout()
  analyze_button = QPushButton("ANALYZE PROGRAM POLICY")
  analyze_button.clicked.connect(self.analyze_remote_program)
  policy_actions.addWidget(analyze_button)
  history_button = QPushButton("POLICY VERSION HISTORY")
  history_button.setStyleSheet("background:#475569")
  history_button.clicked.connect(self.view_remote_policy_history)
  policy_actions.addWidget(history_button)
  propose_button = QPushButton("PROPOSE CLEAR IN-SCOPE HOSTS")
  propose_button.clicked.connect(self.propose_clear_remote_hostnames)
  policy_actions.addWidget(propose_button)
  policy_layout.addLayout(policy_actions)
  self.remote_policy_status = QLabel("Select a project, then analyze its official programme policy.")
  self.remote_policy_status.setWordWrap(True)
  self.remote_policy_status.setStyleSheet("color:#e9c46a;padding:6px")
  policy_layout.addWidget(self.remote_policy_status)
  self.remote_policy_summary = QTextEdit()
  self.remote_policy_summary.setReadOnly(True)
  self.remote_policy_summary.setMaximumHeight(180)
  self.remote_policy_summary.setPlaceholderText("The extracted do's, don'ts, rate limits and execution restrictions will appear here.")
  policy_layout.addWidget(self.remote_policy_summary)
  self.remote_policy_assets = QTableWidget(0, 6)
  self.remote_policy_assets.setHorizontalHeaderLabels(["ID", "Candidate", "Classification", "Confidence", "Review", "Type"])
  self.remote_policy_assets.setSelectionBehavior(QTableWidget.SelectRows)
  self.remote_policy_assets.setSelectionMode(QTableWidget.SingleSelection)
  self.remote_policy_assets.setEditTriggers(QTableWidget.NoEditTriggers)
  self.remote_policy_assets.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
  self.remote_policy_assets.horizontalHeader().setStretchLastSection(True)
  self.remote_policy_assets.itemSelectionChanged.connect(self.show_remote_policy_asset_evidence)
  policy_layout.addWidget(self.remote_policy_assets, 1)
  self.remote_policy_asset_details = QTextEdit()
  self.remote_policy_asset_details.setReadOnly(True)
  self.remote_policy_asset_details.setMaximumHeight(105)
  self.remote_policy_asset_details.setPlaceholderText("Select a candidate to inspect its original policy evidence.")
  policy_layout.addWidget(self.remote_policy_asset_details)
  self.remote_policy_review_note = QLineEdit()
  self.remote_policy_review_note.setPlaceholderText("Optional review note")
  policy_layout.addWidget(self.remote_policy_review_note)
  review_row = QHBoxLayout()
  for label, decision in [("Accept candidate", "accepted"), ("Reject candidate", "rejected"), ("Defer candidate", "deferred")]:
   button = QPushButton(label)
   button.clicked.connect(lambda checked=False, value=decision: self.review_remote_policy_asset(value))
   review_row.addWidget(button)
  add_button = QPushButton("ADD ACCEPTED TO PROPOSED SCOPE")
  add_button.setStyleSheet("background:#475569")
  add_button.clicked.connect(self.add_remote_candidate_to_scope)
  review_row.addWidget(add_button)
  approve_button = QPushButton("APPROVE EXACT SCOPE")
  approve_button.setStyleSheet("background:#12845a")
  approve_button.clicked.connect(self.approve_remote_scope)
  review_row.addWidget(approve_button)
  policy_layout.addLayout(review_row)
  tabs.addTab(policy_page, "Policy & scope")

  credentials_page = QWidget()
  credentials_layout = QVBoxLayout(credentials_page)
  credentials_layout.addWidget(QLabel(
   "Optional researcher-owned test accounts. Secrets are write-only and encrypted on the server. "
   "Only use accounts and hosts you are authorized to test."
  ))
  credential_form = QFormLayout()
  self.remote_credential_host = QComboBox()
  self.remote_credential_name = QLineEdit()
  self.remote_credential_name.setPlaceholderText("e.g. owner-account")
  self.remote_credential_role = QLineEdit()
  self.remote_credential_role.setPlaceholderText("e.g. owner / standard")
  self.remote_credential_type = QComboBox()
  self.remote_credential_type.addItem("Bearer token", "bearer")
  self.remote_credential_type.addItem("Cookie header", "cookie")
  self.remote_credential_secret = QLineEdit()
  self.remote_credential_secret.setEchoMode(QLineEdit.Password)
  self.remote_credential_secret.setPlaceholderText("Short-lived token or Cookie header")
  credential_form.addRow("Approved host", self.remote_credential_host)
  credential_form.addRow("Profile name", self.remote_credential_name)
  credential_form.addRow("Account role", self.remote_credential_role)
  credential_form.addRow("Credential type", self.remote_credential_type)
  credential_form.addRow("Secret", self.remote_credential_secret)
  credentials_layout.addLayout(credential_form)
  credential_actions = QHBoxLayout()
  save_credential = QPushButton("SAVE ENCRYPTED TEST ACCOUNT")
  save_credential.clicked.connect(self.add_remote_test_credential)
  credential_actions.addWidget(save_credential)
  refresh_credential = QPushButton("Refresh profiles")
  refresh_credential.setStyleSheet("background:#475569")
  refresh_credential.clicked.connect(self.refresh_remote_test_credentials)
  credential_actions.addWidget(refresh_credential)
  delete_credential = QPushButton("Delete selected")
  delete_credential.setStyleSheet("background:#7f1d1d")
  delete_credential.clicked.connect(self.delete_remote_test_credential)
  credential_actions.addWidget(delete_credential)
  credentials_layout.addLayout(credential_actions)
  self.remote_credential_profiles = QListWidget()
  credentials_layout.addWidget(self.remote_credential_profiles, 1)
  tabs.addTab(credentials_page, "Test accounts")

  owned_page = QWidget()
  owned_layout = QVBoxLayout(owned_page)
  owned_layout.addWidget(QLabel(
   "Register synthetic records created by your own test accounts. Registration does not send requests."
  ))
  owned_form = QFormLayout()
  self.remote_owned_host = QComboBox()
  self.remote_owned_owner_profile = QComboBox()
  self.remote_owned_endpoint = QLineEdit()
  self.remote_owned_endpoint.setPlaceholderText("https://approved.example/api/items/{id}")
  self.remote_owned_reference = QLineEdit()
  self.remote_owned_reference.setEchoMode(QLineEdit.Password)
  self.remote_owned_reference.setPlaceholderText("Synthetic test-record identifier")
  self.remote_owned_attestation = QLineEdit()
  self.remote_owned_attestation.setPlaceholderText("How the owner test account accessed this record")
  owned_form.addRow("Approved host", self.remote_owned_host)
  owned_form.addRow("Owner test account", self.remote_owned_owner_profile)
  owned_form.addRow("HTTPS endpoint template", self.remote_owned_endpoint)
  owned_form.addRow("Record identifier", self.remote_owned_reference)
  owned_form.addRow("Ownership note", self.remote_owned_attestation)
  owned_layout.addLayout(owned_form)
  owned_actions = QHBoxLayout()
  save_owned = QPushButton("REGISTER OWNED TEST RESOURCE")
  save_owned.clicked.connect(self.add_remote_owned_resource)
  owned_actions.addWidget(save_owned)
  refresh_owned = QPushButton("Refresh resources")
  refresh_owned.setStyleSheet("background:#475569")
  refresh_owned.clicked.connect(self.refresh_remote_owned_resources)
  owned_actions.addWidget(refresh_owned)
  delete_owned = QPushButton("Delete selected")
  delete_owned.setStyleSheet("background:#7f1d1d")
  delete_owned.clicked.connect(self.delete_remote_owned_resource)
  owned_actions.addWidget(delete_owned)
  owned_layout.addLayout(owned_actions)
  self.remote_owned_resources = QListWidget()
  owned_layout.addWidget(self.remote_owned_resources, 1)
  tabs.addTab(owned_page, "Owned test data")

  close_row = QHBoxLayout()
  close_row.addStretch(1)
  close_button = QPushButton("CLOSE")
  close_button.setStyleSheet("background:#475569")
  close_button.clicked.connect(dialog.accept)
  close_row.addWidget(close_button)
  outer.addLayout(close_row)
  self.remote_tools_dialog = dialog

 def open_remote_project_tools(self):
  if not self.remote_project_id or not self.remote_project:
   QMessageBox.information(self, "Project tools", "Create or select a project first.")
   return
  self.remote_tools_dialog.show()
  self.remote_tools_dialog.raise_()
  self.remote_tools_dialog.activateWindow()
  self.refresh_remote_policy_assets()
  self.refresh_remote_test_credentials()
  self.refresh_remote_owned_resources()

 def approve_remote_scope(self):
  project_id = self.remote_project_id
  if not self.api_client or not project_id or not self.remote_project:
   QMessageBox.warning(self, "Approve scope", "Select a remote project first.")
   return

  policy_text = self.remote_policy_text.toPlainText().strip()
  if not policy_text:
   QMessageBox.warning(
    self, "Approve scope",
    "Analyze the programme URL or paste its official policy text first."
   )
   return

  try:
   assets = self.api_client.list_project_resource(project_id, "assets")
   included = [
    asset.get("host", "") for asset in assets
    if asset.get("included") and asset.get("host")
   ]
   excluded = [
    asset.get("host", "") for asset in assets
    if not asset.get("included") and asset.get("host")
   ]
   if not included:
    QMessageBox.warning(
     self, "Approve scope",
     "There are no included assets. Review policy candidates and add "
     "explicitly authorized assets to proposed scope first."
    )
    return

   details = "Included assets to approve:\n" + "\n".join(included)
   if excluded:
    details += "\n\nExcluded assets (will remain unapproved):\n" + "\n".join(excluded)
   answer = QMessageBox.question(
    self,
    "Confirm exact remote scope",
    details + "\n\nApprove only this exact included asset list?",
    QMessageBox.Yes | QMessageBox.No,
    QMessageBox.No,
   )
   if answer != QMessageBox.Yes:
    return

   self.api_client.approve_scope(project_id, policy_text)
   self.remote_project = self.api_client.get_project(project_id)
   self.remote_tools_dialog.accept()
   self.remote_stage_status.setText(
    "SCOPE APPROVED — the exact included assets are saved. You can now start the cloud hunt."
   )
   self.refresh_remote_test_credentials()
   self.remote_start_hunt_button.setEnabled(True)
   self.remote_selected_project_title.setText(self.remote_project.get("name", "Selected project"))
   self.remote_scope_hint.setText("Scope approved. You can now start a cloud hunt for the approved assets.")
   self.remote_project_details.setPlainText(
    f"Project: {self.remote_project.get('name')}\n"
    "Scope approved on the cloud server.\n"
    f"Approved included assets: {len(included)}\n"
    f"Excluded assets: {len(excluded)}\n\n"
    "Use START CLOUD HUNT to queue discovery for each approved asset."
   )
   self.remote_policy_status.setText(
    f"Remote scope approved: {len(included)} included asset(s). "
    "Excluded assets remain unapproved."
   )
   self.refresh_remote_workspace()
  except APIError as exc:
   QMessageBox.warning(self, "Approve scope", str(exc))
  except Exception as exc:
   QMessageBox.warning(self, "Approve scope", f"Could not approve scope: {exc}")

 def start_remote_hunt(self):
  project = self.remote_project
  project_id = self.remote_project_id
  if not self.api_client or not project or not project_id:
   QMessageBox.warning(self, "Cloud hunt", "Select a remote project first.")
   return
  if not project.get("scope_approved"):
   QMessageBox.warning(self, "Cloud hunt", "Approve the exact programme scope before starting a hunt.")
   return
  self.remote_start_hunt_button.setEnabled(False)
  self.remote_start_hunt_button.setText("QUEUEING HUNT…")
  self.remote_stage_status.setText("Queueing approved assets on the cloud worker…")
  self._hunt_queue_thread = HuntQueueThread(
   self.api_client.base_url, self.api_client._token, project_id, self
  )
  self._hunt_queue_thread.succeeded.connect(self._remote_hunt_queue_succeeded)
  self._hunt_queue_thread.failed.connect(self._remote_hunt_queue_failed)
  self._hunt_queue_thread.start()

 def _remote_hunt_queue_succeeded(self, result):
  active = int(result.get("already_active") or 0)
  queued = result.get("queued") or []
  if active:
   QMessageBox.information(
    self, "Hunt already active",
    f"This project already has {active} queued, running or paused hunt(s)."
   )
   self.refresh_remote_workspace()
   return
  summary = "\n".join(f"Job #{job_id}: {host}" for job_id, host in queued)
  self.statusBar().showMessage(
   f"Queued {len(queued)} cloud hunt(s) for project #{self.remote_project_id}."
  )
  self.refresh_remote_workspace()
  self.remote_workspace_tabs.show()
  self.remote_workspace_tabs.setCurrentWidget(self.remote_findings_table)
  self.remote_stage_status.setText(
   "HUNT QUEUED — the independent cloud worker will process every approved asset. "
   "Findings and progress will appear below."
  )
  QMessageBox.information(
   self, "Cloud hunts queued",
   f"Queued {len(queued)} independent cloud hunt job(s):\n\n{summary}\n\n"
   "They continue independently of this desktop. The worker performs "
   "policy-aware, bounded HTTPS GET assessment: attack-surface and API "
   "discovery, security-configuration checks, response and client-side "
   "analysis, and evidence correlation. It does not perform destructive "
   "or state-changing exploit tests; potential leads still require review.",
  )

 def _remote_hunt_queue_failed(self, message):
  self.remote_start_hunt_button.setEnabled(True)
  self.remote_start_hunt_button.setText("▶  START HUNT")
  self.remote_stage_status.setText("HUNT COULD NOT BE QUEUED — review the error and retry.")
  QMessageBox.warning(self, "Cloud hunt", message)

 def analyze_remote_program(self):
  project = self.remote_project
  project_id = self.remote_project_id
  if not self.api_client or not project or not project_id:
   QMessageBox.warning(self, "Program analysis", "Select an active or draft remote project first.")
   return
  if str(project.get("status", "")).lower() == "deleted":
   QMessageBox.warning(self, "Program analysis", "Archived projects cannot be analyzed. Restore the project first.")
   return
  if not (project.get("programme_url") or "").strip():
   QMessageBox.warning(self, "Program analysis", "This project has no programme URL.")
   return
  policy_text = self.remote_policy_text.toPlainText().strip()
  self.remote_analyze_button.setEnabled(False)
  self.remote_policy_summary.clear()
  self.remote_policy_status.setText(
   "Analyzing policy in the background. No discovered target assets are being contacted."
  )
  self._analysis_thread = RemoteAPICallThread(
   self.api_client.base_url, self.api_client._token,
   "analyze_program", (project_id,), {"policy_text": policy_text}, self,
  )
  self._analysis_thread.succeeded.connect(self._handle_remote_program_analysis)
  self._analysis_thread.failed.connect(self._handle_remote_program_analysis_error)
  self._analysis_thread.start()

 def _handle_remote_program_analysis(self, result):
  project = self.remote_project or {}
  project_id = self.remote_project_id
  self.remote_policy_status.setText(
   "Policy analysis saved. Candidate assets require independent review; "
   "none have been approved."
  )
  analysis = result.get("analysis") or {}
  extracted_text = analysis.get("policy_text", "")
  if extracted_text:
   self.remote_policy_text.setPlainText(extracted_text)
  self.refresh_remote_policy_assets()

  controls = analysis.get("execution_controls") or {}
  rules = analysis.get("rules") or {}
  scope = analysis.get("scope") or {}
  summary = [
   f"PROGRAMME: {analysis.get('title') or project.get('name')}",
   f"POLICY SOURCE: {analysis.get('source', 'unknown')}",
   f"PROGRAMME PLATFORM: {(analysis.get('provider') or {}).get('name', 'Unknown / generic')}",
   f"ANALYSIS MODE: {(analysis.get('provider') or {}).get('analysis_mode', 'generic_policy_parser')}",
   f"EXTRACTION CONFIDENCE: {(analysis.get('policy') or {}).get('extraction_confidence', 'low').upper()}",
   f"SCOPE CANDIDATES: {len(scope.get('included_candidates', []))} included · {len(scope.get('excluded_candidates', []))} excluded · {len(scope.get('ambiguous_candidates', []))} ambiguous",
   "",
   "DOs / EXECUTION CONTROLS",
   f"Passive discovery: {'ALLOWED' if controls.get('passive_discovery_allowed') else 'BLOCKED BY POLICY'}",
   f"Active automated testing: {'ALLOWED SUBJECT TO APPROVAL' if controls.get('active_automated_testing_allowed') else 'BLOCKED BY POLICY'}",
   f"Minimum request delay: {controls.get('minimum_request_delay_seconds', 'not extracted')} seconds",
   f"Rate-limit evidence: {' ; '.join(controls.get('rate_limit_evidence', [])[:5]) or 'No explicit rate limit extracted'}",
   "",
   "POLICY RULES / DON'Ts",
  ]
  for category, entries in rules.items():
   summary.append(f"{category.replace('_', ' ').title()}:")
   summary.extend(f"  • {entry}" for entry in entries[:12])
  summary += [
   "",
   "SCOPE CANDIDATES ARE NOT AUTHORIZATION.",
   "Excluded assets override conflicting inclusions. Wildcards, CIDRs, path-limited URLs and ambiguous assets require separate human interpretation.",
   "",
   "WARNINGS",
  ]
  summary.extend(f"• {warning}" for warning in analysis.get("warnings", []))
  self.remote_project_details.setPlainText("\n".join(summary))
  self.remote_policy_summary.setPlainText("\n".join(summary))
  self.remote_stage_status.setText(
   "POLICY ANALYZED AND SAVED — review the original policy, extracted do's and don'ts, "
   "and every candidate asset before approving the exact scope."
  )
  self.open_remote_project_tools()
  self.remote_analyze_button.setEnabled(True)

  self.statusBar().showMessage(
   f"Policy analysis saved for remote project #{project_id}."
  )


 def _handle_remote_program_analysis_error(self, message):
  self.remote_policy_status.setText(
   "Automatic retrieval failed. Paste the official policy text and analyze it again."
  )
  self.remote_analyze_button.setEnabled(True)
  self.open_remote_project_tools()
  QMessageBox.warning(self, "Program analysis", message)

 def _selected_remote_policy_asset(self):
  if not getattr(self, "remote_policy_assets", None):
   return None
  row = self.remote_policy_assets.currentRow()
  if row < 0:
   return None
  item = self.remote_policy_assets.item(row, 0)
  if item is None:
   return None
  try:
   return int(item.data(Qt.UserRole))
  except (TypeError, ValueError):
   return None

 def refresh_remote_policy_assets(self):
  if not self.api_client or not self.remote_project_id:
   return

  history = self.api_client.list_program_policies(self.remote_project_id)
  self._remote_policy_asset_data = {}
  self.remote_policy_assets.setRowCount(0)

  for policy in history:
   version = policy.get("version_number", "?")
   for candidate in policy.get("assets", []):
    asset_id = int(candidate["id"])
    self._remote_policy_asset_data[asset_id] = {
     **candidate,
     "policy_version": version,
     "policy_id": policy.get("id"),
     "source_url": policy.get("source_url", ""),
    }

    row = self.remote_policy_assets.rowCount()
    self.remote_policy_assets.insertRow(row)

    values = [
     str(asset_id),
     str(candidate.get("asset", "")),
     str(candidate.get("disposition", "ambiguous")),
     str(candidate.get("confidence", "low")),
     str(candidate.get("review_status", "pending")),
     str(candidate.get("asset_type", "hostname")),
    ]
    for column, value in enumerate(values):
     cell = QTableWidgetItem(value)
     if column == 0:
      cell.setData(Qt.UserRole, asset_id)
     self.remote_policy_assets.setItem(row, column, cell)

  self.remote_policy_asset_details.clear()
  self.remote_policy_status.setText(
   f"Loaded {len(self._remote_policy_asset_data)} candidates. "
   "Human review is separate from scope approval."
  )

 def show_remote_policy_asset_evidence(self):
  asset_id = self._selected_remote_policy_asset()
  if asset_id is None:
   return

  candidate = getattr(self, "_remote_policy_asset_data", {}).get(asset_id)
  if not candidate:
   return

  details = {
   "candidate_id": asset_id,
   "asset": candidate.get("asset"),
   "asset_type": candidate.get("asset_type"),
   "original_policy_classification": candidate.get("disposition"),
   "confidence": candidate.get("confidence"),
   "human_review_status": candidate.get("review_status"),
   "review_note": candidate.get("review_note"),
   "policy_version": candidate.get("policy_version"),
   "source_url": candidate.get("source_url"),
   "original_evidence": candidate.get("evidence", []),
  }
  self.remote_policy_asset_details.setPlainText(
   json.dumps(details, indent=2, ensure_ascii=False, default=str)
  )

 def review_remote_policy_asset(self, decision):
  asset_id = self._selected_remote_policy_asset()
  if asset_id is None:
   QMessageBox.warning(
    self, "Candidate review", "Select a candidate first."
   )
   return

  if not self.api_client or not self.remote_project_id:
   return

  note = self.remote_policy_review_note.text().strip()
  try:
   self.api_client.review_program_asset(
    self.remote_project_id, asset_id, decision, note
   )
   self.refresh_remote_policy_assets()
   self.statusBar().showMessage(
    f"Candidate #{asset_id} marked {decision}. No scope approval granted."
   )
  except APIError as exc:
   QMessageBox.warning(self, "Candidate review", str(exc))
  except Exception as exc:
   QMessageBox.warning(
    self, "Candidate review", f"Could not refresh candidates: {exc}"
   )

 def propose_clear_remote_hostnames(self):
  if not self.api_client or not self.remote_project_id:
   QMessageBox.warning(
    self, "Proposed scope", "Select a remote project first."
   )
   return

  answer = QMessageBox.question(
   self,
   "Propose clear in-scope hostnames",
   "Automatically add only exact hostnames that the latest policy "
   "extractor classified as explicitly included with medium confidence?\n\n"
   "Excluded assets, wildcard entries, IP ranges, IP literals, URLs and "
   "ambiguous candidates will be skipped. Nothing is authorized until "
   "you review and approve the complete proposed scope.",
   QMessageBox.Yes | QMessageBox.No,
   QMessageBox.No,
  )
  if answer != QMessageBox.Yes:
   return

  try:
   result = self.api_client.propose_clear_program_hostnames(
    self.remote_project_id
   )
   self.refresh_remote_policy_assets()
   self.remote_project = self.api_client.get_project(self.remote_project_id)
   self.remote_start_hunt_button.setEnabled(
    bool(self.remote_project.get("scope_approved"))
   )
   proposed = result.get("proposed", [])
   summary = "\n".join(
    item.get("host", "") for item in proposed
   ) or "No new exact hostnames qualified."
   self.remote_policy_status.setText(
    f"Proposed {result.get('proposed_count', 0)} clear hostname(s). "
    "Scope is not approved."
   )
   QMessageBox.information(
    self,
    "Proposed scope updated",
    f"Policy version: {result.get('policy_version')}\n"
    f"New exact hostnames: {result.get('proposed_count', 0)}\n"
    f"Already present: {result.get('skipped_existing_count', 0)}\n\n"
    f"{summary}\n\n"
    "Review the proposed scope, then use APPROVE REMOTE SCOPE. "
    "No target testing has started.",
   )
  except APIError as exc:
   QMessageBox.warning(self, "Proposed scope", str(exc))
  except Exception as exc:
   QMessageBox.warning(
    self, "Proposed scope", f"Could not propose hostnames: {exc}"
   )

 def add_remote_candidate_to_scope(self):
  asset_id = self._selected_remote_policy_asset()
  if asset_id is None:
   QMessageBox.warning(
    self, "Proposed scope", "Select a candidate first."
   )
   return

  candidate = getattr(
   self, "_remote_policy_asset_data", {}
  ).get(asset_id, {})

  if candidate.get("review_status") != "accepted":
   QMessageBox.warning(
    self, "Proposed scope",
    "Accept the candidate through human review before adding it."
   )
   return

  if candidate.get("disposition") == "excluded":
   QMessageBox.warning(
    self, "Proposed scope",
    "This candidate was classified as excluded by the policy analysis."
   )
   return

  answer = QMessageBox.question(
   self,
   "Add to proposed scope",
   "Add this accepted candidate to proposed scope?\\n\\n"
   f"{candidate.get('asset', '')}\\n\\n"
   "This does NOT approve the asset or authorize testing. "
   "Separate scope approval is still required.",
   QMessageBox.Yes | QMessageBox.No,
   QMessageBox.No,
  )
  if answer != QMessageBox.Yes:
   return

  try:
   result = self.api_client.add_program_asset_to_scope(
    self.remote_project_id, asset_id
   )
   QMessageBox.information(
    self, "Proposed scope",
    result.get(
     "message",
     "Added to proposed scope only. The asset is not approved."
    )
   )
   self.statusBar().showMessage(
    f"Candidate #{asset_id} added as an unapproved scope entry."
   )
  except APIError as exc:
   QMessageBox.warning(self, "Proposed scope", str(exc))

 def view_remote_policy_history(self):
  project_id = self.remote_project_id

  if not self.api_client or not project_id:
   QMessageBox.warning(
    self, "Policy history",
    "Select a remote project first."
   )
   return

  try:
   history = self.api_client.list_program_policies(project_id)

   self.remote_project_details.setPlainText(
    "SAVED PROGRAM POLICY VERSIONS\n"
    "=============================\n"
    + json.dumps(history, indent=2, ensure_ascii=False, default=str)
    + "\n\nCandidate assets shown in this history are not approved scope."
   )

   self.remote_policy_status.setText(
    "Policy history loaded. Review each version and its extracted candidates."
   )
   self.refresh_remote_policy_assets()

  except APIError as exc:
   QMessageBox.warning(self, "Policy history", str(exc))

  except Exception as exc:
   QMessageBox.warning(
    self, "Policy history",
    f"Unexpected error: {exc}"
   )

 def begin_new_remote_project(self):
  self.remote_project_id = None
  self.remote_project = None
  self.cloud_workspace.clear_workspace()
  self.remote_project_list.clearSelection()
  self.remote_project_name.clear()
  self.remote_project_url.clear()
  self.remote_policy_text.clear()
  self.remote_policy_summary.clear()
  self.remote_project_details.clear()
  self.remote_tools_dialog.hide()
  self.remote_create_project_box.show()
  self.remote_create_project_button.setEnabled(True)
  self.remote_analyze_button.hide()
  self.remote_start_hunt_button.hide()
  self.remote_start_hunt_button.setEnabled(False)
  self.remote_scope_hint.hide()
  self.remote_report_format.hide()
  self.remote_download_report_button.hide()
  self.remote_new_project_button.hide()
  self.remote_workspace_tabs.hide()
  self.remote_selected_project_title.hide()
  self.remote_stage_status.setText(
   "Create a project with its official programme URL and name, then analyze the programme policy."
  )
  self.statusBar().showMessage("Ready for a new authorized programme project.")

 def download_remote_report(self):
  if not self.api_client or not self.remote_project_id:
   QMessageBox.warning(self, "Report", "Select a project first.")
   return
  fmt = self.remote_report_format.currentData()
  extension = "md" if fmt == "markdown" else fmt
  project_name = (self.remote_project or {}).get("name", "bughunter-project")
  safe_name = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in project_name).strip("_")
  filename = f"{safe_name or 'bughunter-project'}_security_report.{extension}"
  download_dir = Path.home() / "Downloads"
  download_dir.mkdir(parents=True, exist_ok=True)
  destination, _ = QFileDialog.getSaveFileName(
   self, "Download security assessment report",
   str(download_dir / filename),
   "All files (*)",
  )
  if not destination:
   return
  try:
   payload = self.api_client.download_report(self.remote_project_id, fmt)
   Path(destination).write_bytes(payload)
   workspace = getattr(self, "cloud_workspace", None)
   if workspace is not None:
    try:
     jobs = self.api_client.list_project_resource(self.remote_project_id, "jobs")
     hunt_jobs = [job for job in jobs if job.get("job_type") == "Automated hunt"]
     if hunt_jobs:
      latest_hunt_id = max(int(job.get("id", 0)) for job in hunt_jobs)
      workspace._settings.setValue(
       f"reports/notified/project_{self.remote_project_id}", str(latest_hunt_id)
      )
    except APIError:
     pass
    workspace.remote_stage_status.setText(
     "HUNT FINISHED — report downloaded. You can download it again in another format."
    )
   QMessageBox.information(
    self, "Report downloaded",
    f"Your first-person security report was saved to:\n{destination}\n\n"
    "Review all findings and evidence before submitting it to the programme."
   )
  except APIError as exc:
   QMessageBox.warning(self, "Report download", str(exc))
  except Exception as exc:
   QMessageBox.warning(self, "Report download", f"Could not save report: {exc}")

 def refresh_remote_projects(self):
  workspace = getattr(self, "cloud_workspace", None)
  if workspace is not None:
   workspace.refresh_projects()
  elif not self.api_client or not self.api_client.authenticated:
   return

 def new_remote_project(self):
  if not self.api_client:
   return

  name = self.remote_project_name.text().strip()
  programme_url = self.remote_project_url.text().strip()

  if not name:
   QMessageBox.warning(self, "Create project", "Enter a project name.")
   return
  if not programme_url.lower().startswith("https://"):
   QMessageBox.warning(self, "Create project", "Enter the official programme URL beginning with https://.")
   return

  try:
   project = self.api_client.create_project(name, programme_url)
   self.remote_project_name.clear()
   self.remote_project_url.clear()
   self.refresh_remote_projects()
   self.remote_project_id = int(project["id"])
   self.remote_project = project
   self.remote_policy_text.clear()
   self.remote_selected_project_title.setText(project.get("name", "New project"))
   self.remote_scope_hint.setText("Project created. Review the policy analysis and approve the exact included assets before starting a hunt.")
   self.remote_project_details.setPlainText(
    f"Created remote project #{project['id']}\n"
    f"Name: {project['name']}\n"
    f"Status: {project['status']}\n"
    f"Programme URL: {project.get('programme_url', '') or 'Not supplied'}\n\n"
    "The project is stored on the central API server."
   )
   self.remote_create_project_box.hide()
   self.remote_analyze_button.show()
   self.remote_selected_project_title.show()
   self.remote_stage_status.setText(
    "PROJECT CREATED — next, press ANALYZE PROJECT. The programme policy will be retrieved and saved before any target testing."
   )
   self.remote_analyze_button.setEnabled(True)
   self.remote_workspace_tabs.hide()
   self.remote_start_hunt_button.hide()
   self.refresh_remote_workspace()
   QMessageBox.information(
    self, "Project created",
    f"Project '{project.get('name')}' was created. Next step: Analyze Project."
   )
  except APIError as exc:
   QMessageBox.warning(self, "Create project", str(exc))

 def select_remote_project(self, item):
  project_id = item.data(Qt.UserRole)
  if not project_id or not self.api_client:
   return

  try:
   project = self.api_client.get_project(int(project_id))
   self.remote_project_id = int(project_id)
   self.remote_project = project
   self.remote_policy_text.clear()
   self.remote_selected_project_title.setText(project.get("name", "Selected project"))
   self.remote_scope_hint.setText(
    "Scope approved. Start a cloud hunt." if project.get("scope_approved")
    else "Next: review the official programme policy and approve the exact authorized assets."
   )
   self.remote_start_hunt_button.setEnabled(
    bool(project.get("scope_approved"))
    and str(project.get("status", "")).lower() != "deleted"
   )
   self.remote_project_details.setPlainText(
    f"Project ID: {project.get('id')}\n"
    f"Name: {project.get('name')}\n"
    f"Status: {project.get('status')}\n"
    f"Programme URL: {project.get('programme_url') or 'Not supplied'}\n"
    f"Description: {project.get('description') or 'None'}\n"
    f"Scope approved: {'YES' if project.get('scope_approved') else 'NO'}\n"
    f"Created: {project.get('created_at')}\n\n"
    "Cloud hunts are queued on the central server and continue independently "
    "of this desktop session."
   )
   self.statusBar().showMessage(
    f"Selected remote project #{project_id}: {project.get('name')}"
   )
   self.refresh_remote_test_credentials()
   self.refresh_remote_workspace()
  except APIError as exc:
   QMessageBox.warning(self, "Project details", str(exc))


 def refresh_remote_test_credentials(self):
  if not self.api_client or not self.remote_project_id:
   return
  try:
   assets = self.api_client.list_project_resource(
    self.remote_project_id, "assets"
   )
   current_host = self.remote_credential_host.currentData()
   self.remote_credential_host.clear()
   for asset in assets:
    if asset.get("included") and asset.get("approved") and asset.get("host"):
     self.remote_credential_host.addItem(
      str(asset["host"]), str(asset["host"])
     )
   if current_host:
    index = self.remote_credential_host.findData(current_host)
    if index >= 0:
     self.remote_credential_host.setCurrentIndex(index)
   profiles = self.api_client.list_test_credential_profiles(
    self.remote_project_id
   )
   self.remote_credential_profiles.clear()
   for profile in profiles:
    label = (
     f"#{profile.get('id')} — {profile.get('host')} | "
     f"{profile.get('name')} [{profile.get('role_label')}] "
     f"({profile.get('auth_type')})"
    )
    item = QListWidgetItem(label)
    item.setData(Qt.UserRole, profile.get("id"))
    self.remote_credential_profiles.addItem(item)
   self.remote_owned_host.clear()
   self.remote_owned_owner_profile.clear()
   for asset in assets:
    if asset.get("included") and asset.get("approved") and asset.get("host"):
     self.remote_owned_host.addItem(str(asset["host"]), str(asset["host"]))
   for profile in profiles:
    if profile.get("enabled"):
     label = (
      f"#{profile.get('id')} — {profile.get('host')} | "
      f"{profile.get('name')} [{profile.get('role_label')}]"
     )
     self.remote_owned_owner_profile.addItem(label, profile.get("id"))
   self.refresh_remote_owned_resources()
  except APIError as exc:
   self.remote_credential_profiles.clear()
   self.remote_credential_profiles.addItem(
    f"Credential profiles unavailable: {exc}"
   )

 def add_remote_test_credential(self):
  if not self.api_client or not self.remote_project_id:
   QMessageBox.warning(self, "Test account", "Select a remote project first.")
   return
  host = self.remote_credential_host.currentData()
  name = self.remote_credential_name.text().strip()
  role = self.remote_credential_role.text().strip()
  auth_type = self.remote_credential_type.currentData()
  secret = self.remote_credential_secret.text()
  if not host or not name or not role or not secret:
   QMessageBox.warning(
    self, "Test account",
    "Select an approved host and enter the profile name, role and secret."
   )
   return
  try:
   profile = self.api_client.add_test_credential_profile(
    self.remote_project_id, host, name, role, auth_type, secret
   )
   self.remote_credential_secret.clear()
   self.remote_credential_name.clear()
   self.remote_credential_role.clear()
   self.refresh_remote_test_credentials()
   QMessageBox.information(
    self, "Test account",
    f"Encrypted profile #{profile.get('id')} saved for {host}. "
    "The secret is not returned by the server."
   )
  except APIError as exc:
   QMessageBox.warning(self, "Test account", str(exc))

 def refresh_remote_owned_resources(self):
  if not self.api_client or not self.remote_project_id:
   return
  try:
   resources = self.api_client.list_researcher_owned_resources(
    self.remote_project_id
   )
   self.remote_owned_resources.clear()
   for resource in resources:
    label = (
     f"#{resource.get('id')} | {resource.get('host')} | "
     f"{resource.get('endpoint_template')} | "
     f"owner profile #{resource.get('owner_profile_id')} | "
     f"fingerprint {str(resource.get('resource_fingerprint', ''))[:12]}…"
    )
    item = QListWidgetItem(label)
    item.setData(Qt.UserRole, resource.get("id"))
    self.remote_owned_resources.addItem(item)
  except APIError as exc:
   self.remote_owned_resources.clear()
   self.remote_owned_resources.addItem(
    f"Owned-resource registry unavailable: {exc}"
   )

 def add_remote_owned_resource(self):
  if not self.api_client or not self.remote_project_id:
   QMessageBox.warning(self, "Owned resource", "Select a remote project first.")
   return
  host = self.remote_owned_host.currentData()
  profile_id = self.remote_owned_owner_profile.currentData()
  endpoint = self.remote_owned_endpoint.text().strip()
  reference = self.remote_owned_reference.text()
  note = self.remote_owned_attestation.text().strip()
  if not host or not profile_id or not endpoint or not reference or len(note) < 20:
   QMessageBox.warning(
    self, "Owned resource",
    "Select an approved host and owner profile, enter the HTTPS endpoint "
    "template and resource identifier, and provide an ownership explanation "
    "of at least 20 characters."
   )
   return
  try:
   resource = self.api_client.add_researcher_owned_resource(
    self.remote_project_id, host, endpoint, profile_id, reference, note
   )
   self.remote_owned_reference.clear()
   self.remote_owned_attestation.clear()
   self.refresh_remote_owned_resources()
   QMessageBox.information(
    self, "Owned resource",
    f"Resource #{resource.get('id')} registered. Its identifier is encrypted "
    "and hidden. No network request was made."
   )
  except APIError as exc:
   QMessageBox.warning(self, "Owned resource", str(exc))

 def delete_remote_owned_resource(self):
  if not self.api_client or not self.remote_project_id:
   return
  item = self.remote_owned_resources.currentItem()
  resource_id = item.data(Qt.UserRole) if item else None
  if not resource_id:
   QMessageBox.warning(self, "Owned resource", "Select a registered resource.")
   return
  answer = QMessageBox.question(
   self, "Delete owned resource",
   "Delete this encrypted researcher-owned resource mapping?",
   QMessageBox.Yes | QMessageBox.No,
   QMessageBox.No,
  )
  if answer != QMessageBox.Yes:
   return
  try:
   self.api_client.delete_researcher_owned_resource(
    self.remote_project_id, resource_id
   )
   self.refresh_remote_owned_resources()
  except APIError as exc:
   QMessageBox.warning(self, "Owned resource", str(exc))


 def delete_remote_test_credential(self):
  if not self.api_client or not self.remote_project_id:
   return
  item = self.remote_credential_profiles.currentItem()
  profile_id = item.data(Qt.UserRole) if item else None
  if not profile_id:
   QMessageBox.warning(self, "Test account", "Select a saved profile to delete.")
   return
  answer = QMessageBox.question(
   self, "Delete test account",
   "Delete this encrypted test-account credential profile?",
   QMessageBox.Yes | QMessageBox.No,
   QMessageBox.No,
  )
  if answer != QMessageBox.Yes:
   return
  try:
   self.api_client.delete_test_credential_profile(
    self.remote_project_id, profile_id
   )
   self.refresh_remote_test_credentials()
  except APIError as exc:
   QMessageBox.warning(self, "Test account", str(exc))


 def select_remote_archived_project(self, item):
  project_id = item.data(Qt.UserRole)
  if not project_id or not self.api_client:
   return

  try:
   project = self.api_client.get_project(int(project_id))
   if str(project.get("status", "")).lower() != "deleted":
    raise APIError(409, "This project is no longer archived. Refresh the list.")

   self.remote_project_id = int(project_id)
   self.remote_project = project
   self.remote_start_hunt_button.setEnabled(False)
   self.remote_project_details.setPlainText(
    f"Archived project #{project.get('id')}\n"
    f"Name: {project.get('name')}\n"
    f"Status: {project.get('status')}\n"
    f"Programme URL: {project.get('programme_url') or 'Not supplied'}\n"
    f"Created: {project.get('created_at')}\n\n"
    "Historical records remain on the server. Restoring returns the project "
    "to draft status and requires scope review and approval again."
   )
   self.refresh_remote_workspace()
   self.refresh_remote_workspace()
  except APIError as exc:
   QMessageBox.warning(self, "Archived project", str(exc))

 def archive_remote_project(self):
  project = self.remote_project
  if not project or not self.remote_project_id:
   QMessageBox.warning(self, "Delete project", "Select an active remote project first.")
   return

  if str(project.get("status", "")).lower() == "deleted":
   QMessageBox.warning(self, "Delete project", "This project is already retired.")
   return

  name = project.get("name", "")
  answer = QMessageBox.question(
   self, "Delete project",
   f"Delete '{name}' from your active projects?\n\n"
   "This is a recoverable deletion: findings, evidence and history are retained in Archived. You can restore the project later.",
   QMessageBox.Yes | QMessageBox.No,
   QMessageBox.No,
  )
  if answer != QMessageBox.Yes:
   return

  confirmation, ok = QInputDialog.getText(
   self, "Confirm deletion",
   f"Type the exact project name to confirm:\n{name}"
  )
  if not ok:
   return

  try:
   self.api_client.archive_project(self.remote_project_id, confirmation)
   self.remote_project_id = None
   self.remote_project = None
   self.refresh_remote_projects()
   QMessageBox.information(self, "Project deleted", f"'{name}' was moved to Archived. Historical records are retained.")
  except APIError as exc:
   QMessageBox.warning(self, "Delete project", str(exc))

 def restore_remote_project(self):
  project = self.remote_project
  if not project or not self.remote_project_id:
   QMessageBox.warning(self, "Restore project", "Select an archived remote project first.")
   return

  if str(project.get("status", "")).lower() != "deleted":
   QMessageBox.warning(self, "Restore project", "Select an archived project first.")
   return

  name = project.get("name", "")
  answer = QMessageBox.question(
   self, "Restore remote project",
   f"Restore '{name}' as a draft?\n\n"
   "Previous scope approvals will be revoked. Review and approve the scope again "
   "before any assessment.",
   QMessageBox.Yes | QMessageBox.No,
   QMessageBox.No,
  )
  if answer != QMessageBox.Yes:
   return

  confirmation, ok = QInputDialog.getText(
   self, "Confirm restoration",
   f"Type the exact project name to confirm:\n{name}"
  )
  if not ok:
   return

  try:
   self.api_client.restore_project(self.remote_project_id, confirmation)
   self.remote_project_id = None
   self.remote_project = None
   self.refresh_remote_projects()
   QMessageBox.information(
    self, "Project restored",
    f"'{name}' was restored as a draft. Re-review its scope before assessment."
   )
  except APIError as exc:
   QMessageBox.warning(self, "Restore project", str(exc))

 def remote_logout(self):
  workspace = getattr(self, "cloud_workspace", None)
  if workspace is not None:
   workspace.timer.stop()
  if self.api_client:
   self.api_client.logout()
   self.api_client.close()
  self.api_client = None
  self.remote_account = None
  self.remote_project_id = None
  self.remote_project = None
  self.show_login()
  self.statusBar().showMessage("Logged out of the central workspace.")


 def metric_card(self,title,value,description):
  card=QFrame()
  card.setObjectName("metricCard")
  card.setStyleSheet("#metricCard{background:#14233a;border:1px solid #263b58;border-radius:10px}")
  layout=QVBoxLayout(card)
  heading=QLabel(title.upper())
  heading.setStyleSheet("color:#91a8c7;font-size:11px;font-weight:700")
  number=QLabel(str(value))
  number.setStyleSheet("font-size:27px;font-weight:800;color:#35a7ff")
  note=QLabel(description)
  note.setStyleSheet("color:#91a8c7;font-size:11px")
  layout.addWidget(heading)
  layout.addWidget(number)
  layout.addWidget(note)
  return card

 def dashboard(self):
  self.setWindowTitle("BugHunter AI — Security Operations Center")
  self.setMinimumSize(1100,760)

  tabs=QTabWidget()

  # OVERVIEW
  overview=QWidget()
  ol=QVBoxLayout(overview)
  header=QLabel("SECURITY OPERATIONS CENTER")
  header.setStyleSheet("font-size:23px;font-weight:800;color:#35a7ff")
  ol.addWidget(header)
  ol.addWidget(QLabel("Your local bug bounty research workspace"))

  metrics=QGridLayout()
  self.metric_projects=QLabel("0")
  self.metric_assets=QLabel("0")
  self.metric_findings=QLabel("0")
  self.metric_checks=QLabel("0")
  self.metric_approved=QLabel("0")

  self.metric_widgets=[]
  for title,widget,note in [
   ("Projects",self.metric_projects,"Research projects"),
   ("Assets",self.metric_assets,"Registered hosts"),
   ("Findings",self.metric_findings,"Recorded findings"),
   ("Checks",self.metric_checks,"Assessment records"),
   ("Approved assets",self.metric_approved,"Included and approved hosts")
  ]:
   card=self.metric_card(title,"0",note)
   value_label=card.findChildren(QLabel)[1]
   if title=="Projects": self.metric_projects=value_label
   elif title=="Assets": self.metric_assets=value_label
   elif title=="Findings": self.metric_findings=value_label
   elif title=="Checks": self.metric_checks=value_label
   else: self.metric_approved=value_label
   self.metric_widgets.append(card)

  for index,card in enumerate(self.metric_widgets):
   metrics.addWidget(card,index//3,index%3)

  ol.addLayout(metrics)

  self.overview_risk_summary = QLabel("Finding risk summary will appear here.")
  self.overview_risk_summary.setWordWrap(True)
  self.overview_risk_summary.setStyleSheet(
   "background:#14233a;border:1px solid #263b58;"
   "border-radius:8px;padding:12px;color:#dce8f8"
  )
  ol.addWidget(self.overview_risk_summary)

  self.overview_project_summary = QLabel(
   "SELECTED PROJECT  |  Select a project to view its summary."
  )
  self.overview_project_summary.setWordWrap(True)
  self.overview_project_summary.setStyleSheet(
   "background:#14233a;border:1px solid #263b58;"
   "border-radius:8px;padding:12px;color:#dce8f8"
  )
  ol.addWidget(self.overview_project_summary)

  quick=QGroupBox("QUICK ACTIONS")
  ql=QHBoxLayout(quick)
  for label,fn in [
   ("CREATE PROJECT",self.new_project),
   ("ANALYZE PROGRAMME",self.analyze),
   ("ADD AUTHORIZED HOST",self.add_host),
   ("RUN SAFE CHECKS",self.hunt),
   ("REFRESH DASHBOARD",self.refresh_overview)
  ]:
   button=QPushButton(label)
   button.clicked.connect(fn)
   ql.addWidget(button)
  ol.addWidget(quick)

  lower=QHBoxLayout()
  projects_box=QGroupBox("RECENT PROJECTS")
  pbl=QVBoxLayout(projects_box)
  self.recent_projects=QListWidget()
  self.recent_projects.itemClicked.connect(self.select_recent_project)
  pbl.addWidget(self.recent_projects)

  activity_box=QGroupBox("RECENT ACTIVITY")
  abl=QVBoxLayout(activity_box)
  self.recent_activity=QListWidget()
  abl.addWidget(self.recent_activity)

  jobs_box=QGroupBox("RECENT ASSESSMENT JOBS")
  jbl=QVBoxLayout(jobs_box)
  self.overview_jobs=QListWidget()
  jbl.addWidget(self.overview_jobs)

  lower.addWidget(projects_box)
  lower.addWidget(activity_box)
  lower.addWidget(jobs_box)
  ol.addLayout(lower)
  tabs.addTab(overview,"Overview")

  # PROJECTS
  p=QWidget()
  pl=QVBoxLayout(p)
  pl.addWidget(QLabel("CREATE AND MANAGE BUG BOUNTY PROJECTS"))
  form=QFormLayout()
  self.pname=QLineEdit()
  self.purl=QLineEdit()
  self.purl.setPlaceholderText("https://programme URL")
  form.addRow("Project name",self.pname)
  form.addRow("Programme URL",self.purl)
  pl.addLayout(form)

  project_row=QHBoxLayout()
  create_button=QPushButton("CREATE PROJECT")
  create_button.clicked.connect(self.new_project)
  project_row.addWidget(create_button)

  delete_button=QPushButton("DELETE PROJECT")
  delete_button.setStyleSheet(
   "background:#b42332;color:white;border-radius:6px;padding:9px 14px;font-weight:600"
  )
  delete_button.clicked.connect(self.delete_project_ui)
  project_row.addWidget(delete_button)

  refresh_button=QPushButton("REFRESH PROJECTS")
  refresh_button.clicked.connect(self.refresh_projects)
  project_row.addWidget(refresh_button)
  pl.addLayout(project_row)

  self.project_list=QListWidget()
  self.project_list.itemClicked.connect(self.select_project)
  pl.addWidget(QLabel("Select an active project to work on:"))
  pl.addWidget(self.project_list)

  archive_box = QGroupBox("ARCHIVED PROJECTS — READ ONLY")
  archive_layout = QVBoxLayout(archive_box)
  archive_layout.addWidget(QLabel(
   "Retired projects remain available for historical review. "
   "They cannot be selected for scanning."
  ))

  self.archived_project_list = QListWidget()
  self.archived_project_list.itemClicked.connect(
   self.show_archived_project
  )
  archive_layout.addWidget(self.archived_project_list)

  restore_row = QHBoxLayout()
  self.restore_project_button = QPushButton("RESTORE SELECTED PROJECT")
  self.restore_project_button.clicked.connect(
   self.restore_archived_project_ui
  )
  restore_row.addWidget(self.restore_project_button)
  archive_layout.addLayout(restore_row)

  self.archived_project_details = QTextEdit()
  self.archived_project_details.setReadOnly(True)
  self.archived_project_details.setMinimumHeight(150)
  self.archived_project_details.setPlaceholderText(
   "Select an archived project to review its retained records."
  )
  archive_layout.addWidget(self.archived_project_details)

  archive_actions = QHBoxLayout()

  view_archive_records_button = QPushButton(
   "VIEW ARCHIVED FINDINGS & REVIEW HISTORY"
  )
  view_archive_records_button.clicked.connect(
   self.view_archived_project_records_ui
  )
  archive_actions.addWidget(view_archive_records_button)

  export_archive_button = QPushButton(
   "EXPORT ARCHIVED PROJECT REPORT"
  )
  export_archive_button.clicked.connect(
   self.export_archived_project_ui
  )
  archive_actions.addWidget(export_archive_button)

  archive_layout.addLayout(archive_actions)

  pl.addWidget(archive_box)
  tabs.addTab(p,"Projects")

  # PROGRAMME AND SCOPE
  s=QWidget()
  sl=QVBoxLayout(s)
  sl.addWidget(QLabel("PROGRAMME POLICY AND AUTHORIZED SCOPE"))
  sl.addWidget(QLabel("Analyze the official programme policy, review its restrictions, then explicitly approve the assets you are authorized to test."))

  self.policy=QTextEdit()
  self.policy.setPlaceholderText("Paste official programme policy text here if automatic retrieval is unavailable.")
  sl.addWidget(self.policy)

  scope_buttons=QHBoxLayout()
  for label,fn in [
   ("ANALYZE PROGRAMME",self.analyze),
   ("ADD HOST",self.add_host),
   ("APPROVE SCOPE",self.approve)
  ]:
   button=QPushButton(label)
   button.clicked.connect(fn)
   scope_buttons.addWidget(button)
  sl.addLayout(scope_buttons)

  self.scope_list=QListWidget()
  sl.addWidget(QLabel("Registered scope assets:"))
  sl.addWidget(self.scope_list)
  tabs.addTab(s,"Programme & Scope")

  # RECON AND TESTING
  testing=QWidget()
  tl=QVBoxLayout(testing)
  tl.addWidget(QLabel("AUTHORIZED SECURITY ASSESSMENT"))
  warning=QLabel(
   "Current implementation: one HTTPS GET request per approved host, "
   "followed by a review of five common HTTP security headers. "
   "This is a limited check, not comprehensive reconnaissance or a full vulnerability scan."
  )
  warning.setWordWrap(True)
  warning.setStyleSheet("background:#382b16;color:#ffd27a;padding:12px;border-radius:7px")
  tl.addWidget(warning)

  self.testing_project_label=QLabel("Selected project: none")
  tl.addWidget(self.testing_project_label)

  test_button=QPushButton("RUN BASIC SECURITY-HEADER ASSESSMENT")
  test_button.clicked.connect(self.hunt)
  tl.addWidget(test_button)

  tl.addWidget(QLabel("BOUNDED WEBSITE ANALYSIS"))
  self.website_url=QLineEdit()
  self.website_url.setPlaceholderText("https://approved-host.example/")
  tl.addWidget(self.website_url)

  self.website_progress=QProgressBar()
  self.website_progress.setRange(0,100)
  self.website_progress.setValue(0)
  tl.addWidget(self.website_progress)

  self.website_status=QLabel("No website analysis running.")
  tl.addWidget(self.website_status)

  analysis_buttons=QHBoxLayout()
  self.start_website_button=QPushButton("START HUNT")
  self.start_website_button.clicked.connect(self.start_website_analysis)
  analysis_buttons.addWidget(self.start_website_button)

  self.stop_website_button=QPushButton("STOP HUNT")
  self.stop_website_button.setEnabled(False)
  self.stop_website_button.clicked.connect(self.stop_website_analysis)
  analysis_buttons.addWidget(self.stop_website_button)
  tl.addLayout(analysis_buttons)

  refresh_test=QPushButton("REFRESH DASHBOARD DATA")
  refresh_test.clicked.connect(self.refresh_all)
  tl.addWidget(refresh_test)

  self.check_list=QListWidget()
  tl.addWidget(QLabel("Recent assessment checks:"))
  tl.addWidget(self.check_list)
  tabs.addTab(testing,"Recon & Testing")

  # FINDINGS
  f=QWidget()
  fl=QVBoxLayout(f)
  fl.addWidget(QLabel("FINDINGS REGISTER"))
  finding_actions=QHBoxLayout()

  create_finding_button=QPushButton("CREATE FINDING")
  create_finding_button.clicked.connect(self.create_finding_ui)
  finding_actions.addWidget(create_finding_button)

  edit_finding_button=QPushButton("EDIT / REVIEW SELECTED")
  edit_finding_button.clicked.connect(self.edit_finding_ui)
  finding_actions.addWidget(edit_finding_button)

  history_finding_button=QPushButton("VIEW REVIEW HISTORY")
  history_finding_button.clicked.connect(self.view_finding_history_ui)
  finding_actions.addWidget(history_finding_button)

  validation_details_button=QPushButton("VIEW VALIDATION DETAILS")
  validation_details_button.setToolTip(
   "Inspect the selected finding's latest passive validation record."
  )
  validation_details_button.clicked.connect(self.view_validation_details_ui)
  finding_actions.addWidget(validation_details_button)

  validate_finding_button=QPushButton("VALIDATE FINDINGS")
  validate_finding_button.setToolTip(
   "Correlate existing passive scan evidence. Makes no network requests."
  )
  validate_finding_button.clicked.connect(self.validate_findings_ui)
  finding_actions.addWidget(validate_finding_button)

  refresh_finding_button=QPushButton("REFRESH")
  refresh_finding_button.clicked.connect(self.refresh_findings)
  finding_actions.addWidget(refresh_finding_button)

  fl.addLayout(finding_actions)
  self.finding_list=QListWidget()
  self.finding_list.itemDoubleClicked.connect(
   lambda item: self.edit_finding_ui()
  )
  fl.addWidget(self.finding_list)

  export_button=QPushButton("EXPORT PROJECT REPORT")
  export_button.clicked.connect(self.export)
  fl.addWidget(export_button)
  tabs.addTab(f,"Findings & Reports")

  # ACTIVITY AND EVIDENCE
  activity=QWidget()
  al=QVBoxLayout(activity)
  al.addWidget(QLabel("PROJECT ACTIVITY HISTORY"))
  al.addWidget(QLabel("Review recorded events, assessment outcomes and project changes."))
  self.activity_list=QListWidget()
  al.addWidget(self.activity_list)
  tabs.addTab(activity,"Activity")

  # TOOLS AND SETTINGS
  tools=QWidget()
  tool_layout=QVBoxLayout(tools)
  tool_layout.addWidget(QLabel("TOOLS & INTEGRATIONS"))
  tool_layout.addWidget(QLabel("Local application configuration and planned integrations."))
  for title,description in [
   ("Nuclei","Not connected in the current dashboard. Integration requires explicit configuration and scope controls."),
   ("OWASP ZAP","Not connected in the current dashboard. A future integration can use its local API."),
   ("HTTPX","Currently used by the basic HTTPS assessment service."),
   ("SQLite database","Local project, scope, finding, check and activity storage."),
   ("AI assistant","Future optional local or cloud-assisted finding analysis. No AI scan is currently running."),
   ("Evidence vault","Implemented: attach local evidence files to projects and findings, calculate SHA-256 hashes, verify file integrity, and manage evidence in the local Evidence Vault.")
  ]:
   group=QGroupBox(title)
   group_layout=QVBoxLayout(group)
   description_label=QLabel(description)
   description_label.setWordWrap(True)
   group_layout.addWidget(description_label)
   tool_layout.addWidget(group)
  tool_layout.addStretch()
  tabs.addTab(tools,"Tools & Settings")


  # ATTACK_SURFACE_WORKFLOW_V1
  attack=QWidget()
  attack_layout=QVBoxLayout(attack)
  attack_layout.addWidget(QLabel("ATTACK SURFACE INVENTORY"))
  attack_layout.addWidget(QLabel("Register discovered URLs and API endpoints belonging to approved assets. Registration does not send requests."))

  endpoint_buttons=QHBoxLayout()
  add_endpoint_button=QPushButton("ADD ENDPOINT")
  add_endpoint_button.clicked.connect(self.add_endpoint_ui)
  endpoint_buttons.addWidget(add_endpoint_button)

  refresh_endpoint_button=QPushButton("REFRESH")
  refresh_endpoint_button.clicked.connect(self.refresh_workflow_views)
  endpoint_buttons.addWidget(refresh_endpoint_button)

  recommend_endpoint_button=QPushButton("GENERATE ENDPOINT TESTS")
  recommend_endpoint_button.clicked.connect(
   self.generate_endpoint_tests_ui
  )
  endpoint_buttons.addWidget(recommend_endpoint_button)

  attack_layout.addLayout(endpoint_buttons)

  self.endpoint_list=QListWidget()
  attack_layout.addWidget(self.endpoint_list)

  attack_layout.addWidget(QLabel("API RESOURCE RELATIONSHIP MAP"))
  attack_layout.addWidget(QLabel(
   "Related API routes grouped by resource. Missing methods are review "
   "suggestions, not confirmed vulnerabilities."
  ))
  self.api_resource_list=QListWidget()
  attack_layout.addWidget(self.api_resource_list)

  # PASSIVE RECONNAISSANCE
  passive_group=QGroupBox("PASSIVE RECONNAISSANCE")
  passive_layout=QVBoxLayout(passive_group)
  passive_layout.addWidget(QLabel(
   "Local DNS resolution and public Certificate Transparency lookups only. "
   "Discovered hosts remain unapproved until you review programme policy."
  ))

  passive_buttons=QHBoxLayout()
  self.passive_start_button=QPushButton("START PASSIVE RECON")
  self.passive_start_button.clicked.connect(self.start_passive_recon_ui)
  passive_buttons.addWidget(self.passive_start_button)

  self.passive_stop_button=QPushButton("STOP")
  self.passive_stop_button.clicked.connect(self.stop_passive_recon_ui)
  self.passive_stop_button.setEnabled(False)
  passive_buttons.addWidget(self.passive_stop_button)

  passive_refresh_button=QPushButton("REFRESH CANDIDATES")
  passive_refresh_button.clicked.connect(self.refresh_passive_candidates)
  passive_buttons.addWidget(passive_refresh_button)
  passive_layout.addLayout(passive_buttons)

  self.passive_progress=QProgressBar()
  self.passive_progress.setRange(0,100)
  passive_layout.addWidget(self.passive_progress)

  self.passive_status=QLabel("Select an approved project to begin.")
  self.passive_status.setWordWrap(True)
  passive_layout.addWidget(self.passive_status)

  passive_layout.addWidget(QLabel("Discovered candidates — not approved:"))
  self.passive_candidate_list=QListWidget()
  passive_layout.addWidget(self.passive_candidate_list)

  review_buttons=QHBoxLayout()
  approve_candidate_button=QPushButton("APPROVE SELECTED CANDIDATE")
  approve_candidate_button.clicked.connect(
   lambda: self.review_passive_candidate(approve=True)
  )
  review_buttons.addWidget(approve_candidate_button)

  reject_candidate_button=QPushButton("REJECT SELECTED CANDIDATE")
  reject_candidate_button.clicked.connect(
   lambda: self.review_passive_candidate(approve=False)
  )
  review_buttons.addWidget(reject_candidate_button)
  passive_layout.addLayout(review_buttons)

  attack_layout.addWidget(passive_group)
  tabs.addTab(attack,"Attack Surface")

  # ASSESSMENT_COVERAGE_TAB
  coverage_tab=QWidget()
  coverage_layout=QVBoxLayout(coverage_tab)
  coverage_layout.addWidget(QLabel("APPROVED ASSET ASSESSMENT COVERAGE"))
  coverage_layout.addWidget(QLabel(
   "Shows recorded assessment activity for included and approved assets. "
   "Discovered candidates are excluded until approved."
  ))

  self.coverage_summary=QLabel("Select a project to view coverage.")
  self.coverage_summary.setWordWrap(True)
  coverage_layout.addWidget(self.coverage_summary)

  coverage_refresh=QPushButton("REFRESH COVERAGE")
  coverage_refresh.clicked.connect(self.refresh_coverage_view)
  coverage_layout.addWidget(coverage_refresh)

  intelligence_refresh=QPushButton("REFRESH PROJECT INTELLIGENCE")
  intelligence_refresh.clicked.connect(self.refresh_project_intelligence)
  coverage_layout.addWidget(intelligence_refresh)

  self.project_intelligence_list=QListWidget()
  self.project_intelligence_list.setMinimumHeight(180)
  coverage_layout.addWidget(self.project_intelligence_list)

  self.coverage_asset_list=QListWidget()
  coverage_layout.addWidget(self.coverage_asset_list)

  self.coverage_notice=QLabel("")
  self.coverage_notice.setWordWrap(True)
  coverage_layout.addWidget(self.coverage_notice)

  tabs.addTab(coverage_tab,"Assessment Coverage")

  # OWASP TEST PLAN
  plan=QWidget()
  plan_layout=QVBoxLayout(plan)
  plan_layout.addWidget(QLabel("OWASP WEB SECURITY TEST PLAN"))
  plan_layout.addWidget(QLabel("Manual assessment tracker. No exploit payloads or target requests are automatically executed."))

  plan_buttons=QHBoxLayout()

  initialize_button=QPushButton("INITIALIZE TEST PLAN")
  initialize_button.clicked.connect(self.initialize_plan_ui)
  plan_buttons.addWidget(initialize_button)

  update_button=QPushButton("UPDATE SELECTED TEST")
  update_button.clicked.connect(self.update_test_ui)
  plan_buttons.addWidget(update_button)

  finding_button=QPushButton("CREATE POTENTIAL FINDING")
  finding_button.clicked.connect(self.create_test_finding)
  plan_buttons.addWidget(finding_button)

  refresh_button=QPushButton("REFRESH")
  refresh_button.clicked.connect(self.refresh_workflow_views)
  plan_buttons.addWidget(refresh_button)

  plan_layout.addLayout(plan_buttons)
  self.test_case_list=QListWidget()
  self.test_case_list.currentItemChanged.connect(
   self.show_test_case_details
  )
  plan_layout.addWidget(self.test_case_list)

  plan_layout.addWidget(QLabel("SELECTED TEST DETAILS"))
  self.test_case_details=QTextEdit()
  self.test_case_details.setReadOnly(True)
  self.test_case_details.setMinimumHeight(150)
  self.test_case_details.setPlaceholderText(
   "Select a test case above to view its assessment details."
  )
  plan_layout.addWidget(self.test_case_details)

  tabs.addTab(plan,"OWASP Test Plan")


  # EVIDENCE_JOB_MANAGER_V1
  evidence_tab=QWidget()
  evidence_layout=QVBoxLayout(evidence_tab)
  evidence_layout.addWidget(QLabel("PROJECT EVIDENCE VAULT"))
  evidence_layout.addWidget(QLabel("Attach and verify locally stored project evidence."))

  evidence_buttons=QHBoxLayout()
  attach_button=QPushButton("ATTACH EVIDENCE")
  attach_button.clicked.connect(self.attach_evidence_ui)
  evidence_buttons.addWidget(attach_button)

  verify_button=QPushButton("VERIFY SHA-256")
  verify_button.clicked.connect(self.verify_evidence_ui)
  evidence_buttons.addWidget(verify_button)

  audit_button=QPushButton("AUDIT EVIDENCE")
  audit_button.clicked.connect(self.audit_evidence_ui)
  evidence_buttons.addWidget(audit_button)

  folder_button=QPushButton("OPEN EVIDENCE FOLDER")
  folder_button.clicked.connect(self.open_evidence_folder_ui)
  evidence_buttons.addWidget(folder_button)

  evidence_refresh=QPushButton("REFRESH")
  evidence_refresh.clicked.connect(self.refresh_evidence_jobs)
  evidence_buttons.addWidget(evidence_refresh)

  evidence_layout.addLayout(evidence_buttons)
  self.evidence_list=QListWidget()
  evidence_layout.addWidget(self.evidence_list)
  tabs.addTab(evidence_tab,"Evidence Vault")

  jobs_tab=QWidget()
  jobs_layout=QVBoxLayout(jobs_tab)
  jobs_layout.addWidget(QLabel("PERSISTENT ASSESSMENT JOB MANAGER"))
  jobs_layout.addWidget(QLabel("Job records and checkpoints only; queued jobs do not execute scans."))

  job_buttons=QHBoxLayout()
  create_job_button=QPushButton("CREATE JOB")
  create_job_button.clicked.connect(self.create_job_ui)
  job_buttons.addWidget(create_job_button)

  update_job_button=QPushButton("UPDATE SELECTED JOB")
  update_job_button.clicked.connect(self.update_job_ui)
  job_buttons.addWidget(update_job_button)

  job_refresh=QPushButton("REFRESH")
  job_refresh.clicked.connect(self.refresh_evidence_jobs)
  job_buttons.addWidget(job_refresh)

  jobs_layout.addLayout(job_buttons)
  self.job_list=QListWidget()
  jobs_layout.addWidget(self.job_list)
  tabs.addTab(jobs_tab,"Job Manager")

  self.setCentralWidget(tabs)
  self.statusBar().showMessage("BugHunter AI ready — select a project before working with scope or findings.")
  self.refresh_projects()
  self.refresh_all()

 def select_recent_project(self,item):
  self.select_project(item)

 def refresh_overview(self):
  # Active projects exclude archived projects; archived projects remain visible
  # in the separate archive panel.
  projects = self.db.scalars(
   select(Project)
   .where(Project.status != "deleted")
   .order_by(Project.id.desc())
  ).all()

  active_project_ids = select(Project.id).where(
   Project.status != "deleted"
  )

  archived_count = self.db.scalar(
   select(func.count(Project.id)).where(Project.status == "deleted")
  ) or 0

  assets = self.db.scalar(
   select(func.count(ScopeAsset.id)).where(
    ScopeAsset.project_id.in_(active_project_ids)
   )
  ) or 0

  findings = self.db.scalar(
   select(func.count(Finding.id)).where(
    Finding.project_id.in_(active_project_ids)
   )
  ) or 0

  checks = self.db.scalar(
   select(func.count(ScanCheck.id)).where(
    ScanCheck.project_id.in_(active_project_ids)
   )
  ) or 0

  approved = self.db.scalar(
   select(func.count(ScopeAsset.id)).where(
    ScopeAsset.project_id.in_(active_project_ids),
    ScopeAsset.approved.is_(True),
    ScopeAsset.included.is_(True)
   )
  ) or 0

  self.metric_projects.setText(str(len(projects)))
  self.metric_assets.setText(str(assets))
  self.metric_findings.setText(str(findings))
  self.metric_checks.setText(str(checks))
  self.metric_approved.setText(str(approved))

  severity_rows = self.db.execute(
   select(
    func.lower(Finding.severity),
    func.count(Finding.id)
   ).where(
    Finding.project_id.in_(active_project_ids)
   ).group_by(func.lower(Finding.severity))
  ).all()

  status_rows = self.db.execute(
   select(
    func.lower(Finding.status),
    func.count(Finding.id)
   ).where(
    Finding.project_id.in_(active_project_ids)
   ).group_by(func.lower(Finding.status))
  ).all()

  project_status_rows = self.db.execute(
   select(
    func.lower(Project.status),
    func.count(Project.id)
   ).where(
    Project.status != "deleted"
   ).group_by(func.lower(Project.status))
  ).all()

  severity = {
   str(name or "unknown"): count for name, count in severity_rows
  }
  statuses = {
   str(name or "unknown"): count for name, count in status_rows
  }
  project_statuses = {
   str(name or "unknown"): count for name, count in project_status_rows
  }

  self.overview_risk_summary.setText(
   "FINDING RISK  |  "
   f"Critical: {severity.get('critical', 0)}    "
   f"High: {severity.get('high', 0)}    "
   f"Medium: {severity.get('medium', 0)}    "
   f"Low: {severity.get('low', 0)}    "
   f"Info: {severity.get('info', 0)}\\n"
   "REVIEW STATUS  |  "
   f"Potential: {statuses.get('potential', 0)}    "
   f"Needs review: {statuses.get('needs_review', 0)}    "
   f"Confirmed: {statuses.get('confirmed', 0)}    "
   f"Rejected: {statuses.get('rejected', 0)}    "
   f"Resolved: {statuses.get('resolved', 0)}\\n"
   "PROJECT STATUS  |  "
   f"Draft: {project_statuses.get('draft', 0)}    "
   f"Active: {project_statuses.get('active', 0)}    "
   f"Other: {sum(project_statuses.values()) - project_statuses.get('draft', 0) - project_statuses.get('active', 0)}    "
   f"Archived: {archived_count}"
  )

  # Selected-project summary.
  if hasattr(self, "overview_project_summary"):
   selected = self.db.get(Project, self.project_id) if self.project_id else None
   if selected:
    project_assets = self.db.scalar(
     select(func.count(ScopeAsset.id)).where(
      ScopeAsset.project_id == selected.id
     )
    ) or 0
    project_approved = self.db.scalar(
     select(func.count(ScopeAsset.id)).where(
      ScopeAsset.project_id == selected.id,
      ScopeAsset.approved.is_(True),
      ScopeAsset.included.is_(True)
     )
    ) or 0
    project_findings = self.db.scalar(
     select(func.count(Finding.id)).where(
      Finding.project_id == selected.id
     )
    ) or 0
    project_evidence = self.db.scalar(
     select(func.count(Evidence.id)).where(
      Evidence.project_id == selected.id
     )
    ) or 0
    self.overview_project_summary.setText(
     f"SELECTED PROJECT  |  {selected.name}  |  "
     f"Status: {selected.status.upper()}  |  "
     f"Scope approved: {'YES' if selected.scope_approved else 'NO'}\\n"
     f"Assets: {project_assets}  |  Approved included assets: {project_approved}  |  "
     f"Findings: {project_findings}  |  Evidence records: {project_evidence}"
    )
   else:
    self.overview_project_summary.setText(
     "SELECTED PROJECT  |  No active project selected."
    )

  self.recent_projects.clear()
  for project in projects[:10]:
   item = QListWidgetItem(
    f"{project.id} — {project.name} [{project.status}]"
   )
   item.setData(Qt.UserRole, project.id)
   self.recent_projects.addItem(item)

  self.recent_activity.clear()
  events = self.db.scalars(
   select(Activity)
   .join(Project, Activity.project_id == Project.id)
   .where(Project.status != "deleted")
   .order_by(Activity.created_at.desc())
   .limit(12)
  ).all()

  for event in events:
   stamp = (
    event.created_at.strftime("%Y-%m-%d %H:%M")
    if event.created_at else "Unknown time"
   )
   self.recent_activity.addItem(
    f"{stamp} | {event.event} | Project #{event.project_id}"
   )

  self.overview_jobs.clear()
  recent_jobs = self.db.scalars(
   select(AssessmentJob)
   .join(Project, AssessmentJob.project_id == Project.id)
   .where(Project.status != "deleted")
   .order_by(AssessmentJob.updated_at.desc())
   .limit(10)
  ).all()

  for job in recent_jobs:
   stamp = (
    job.updated_at.strftime("%Y-%m-%d %H:%M")
    if job.updated_at else "Unknown time"
   )
   self.overview_jobs.addItem(
    f"Job #{job.id} | Project #{job.project_id} | "
    f"{job.job_type} | {job.status.upper()} | "
    f"{job.progress}% | Updated: {stamp}"
   )

  if not recent_jobs:
   self.overview_jobs.addItem("No assessment jobs recorded.")

 def refresh_activity(self):
  if not hasattr(self,"activity_list"):
   return
  self.activity_list.clear()
  query=select(Activity).order_by(Activity.created_at.desc()).limit(100)
  if self.project_id:
   query=query.where(Activity.project_id==self.project_id)
  events=self.db.scalars(query).all()
  for event in events:
   self.activity_list.addItem(
    f"{event.created_at} | Project #{event.project_id} | {event.event} | {event.details}"
   )

 def refresh_checks(self):
  if not hasattr(self,"check_list"):
   return
  self.check_list.clear()
  if not self.project_id:
   self.check_list.addItem("Select a project to view assessment checks.")
   return
  checks=self.db.scalars(
   select(ScanCheck).where(ScanCheck.project_id==self.project_id)
   .order_by(ScanCheck.id.desc()).limit(100)
  ).all()
  for check in checks:
   self.check_list.addItem(
    f"{check.outcome.upper()} | {check.check_name} | {check.asset} | {check.details[:180]}"
   )

 def refresh_coverage_view(self):
  if not hasattr(self, "coverage_asset_list"):
   return

  self.coverage_asset_list.clear()

  if not self.project_id:
   self.coverage_summary.setText("Select a project to view coverage.")
   self.coverage_asset_list.addItem("No project selected.")
   self.coverage_notice.clear()
   return

  try:
   data = get_project_coverage(self.db, self.project_id)
   summary = data["summary"]

   self.coverage_summary.setText(
    f"Project: {data['project_name']}  |  "
    f"Scope approved: {'YES' if data['scope_approved'] else 'NO'}\\n"
    f"Approved assets: {summary['approved_assets']}  |  "
    f"Assessed: {summary['assessed_assets']}  |  "
    f"Not assessed: {summary['unassessed_assets']}  |  "
    f"Coverage: {summary['asset_coverage_percent']}%\\n"
    f"Endpoints: {summary['endpoints_discovered']}  |  "
    f"Assessment checks: {summary['assessment_checks_recorded']}  |  "
    f"Findings: {summary['findings_recorded']}"
   )

   if not data["assets"]:
    self.coverage_asset_list.addItem(
     "No included, approved assets are registered for this project."
    )

   for asset in data["assets"]:
    status = asset["assessment_status"].replace("_", " ").upper()
    names = ", ".join(asset["check_names"][:5]) or "No checks recorded"

    category_details = asset["test_categories"]
    if category_details:
     category_text = "\\n".join(
      f"  {item['category']}: "
      f"{item['completed']}/{item['applicable']} "
      f"({item['completion_percent']}%) — {item['status']} | "
      f"Review: {item['needs_review']} | Blocked: {item['blocked']}"
      for item in category_details
     )
    else:
     category_text = "No test cases explicitly assigned to this asset."

    self.coverage_asset_list.addItem(
     f"{status} | {asset['host']}\\n"
     f"Checks: {asset['checks_completed']} | "
     f"Endpoints: {asset['endpoints_discovered']} | "
     f"Findings: {asset['findings_recorded']}\\n"
     f"Check types: {names}\\n"
     f"Targeted test cases: {asset['test_cases_targeted']}\\n"
     f"Asset test-plan categories:\\n{category_text}\\n"
     f"Last check: {asset['last_check'] or 'Never'}"
    )

   endpoint_lines = [
    "",
    "ENDPOINT-LEVEL ASSESSMENT COVERAGE",
    (
     f"Endpoints with recommendations: "
     f"{summary['endpoints_with_recommendations']}/"
     f"{summary['endpoints_discovered']}"
    ),
    (
     f"Endpoint-linked test cases: "
     f"{summary['endpoint_test_cases']}"
    ),
   ]

   if not data["endpoints"]:
    endpoint_lines.append("No endpoints registered.")
   for endpoint in data["endpoints"]:
    endpoint_lines.append(
     f"#{endpoint['endpoint_id']} | {endpoint['method']} "
     f"| {endpoint['url']}"
    )
    endpoint_lines.append(
     f"  {endpoint['completed']}/{endpoint['applicable']} completed "
     f"({endpoint['completion_percent']}%) | "
     f"Review: {endpoint['needs_review']} | "
     f"Planned: {endpoint['planned']} | "
     f"Blocked: {endpoint['blocked']} | "
     f"Status: {endpoint['status']}"
    )
    if endpoint["categories"]:
     for category in endpoint["categories"]:
      endpoint_lines.append(
       f"  {category['category']}: "
       f"{category['completed']}/{category['applicable']} "
       f"({category['completion_percent']}%)"
      )
    else:
     endpoint_lines.append("  No recommendations assigned.")

   category_lines = [
    "",
    "VULNERABILITY TEST-PLAN COVERAGE",
    (
     f"Completed: {summary['test_cases_completed']}/"
     f"{summary['test_cases_total']} | "
     f"Progress: {summary['test_plan_completion_percent']}%"
    ),
    (
     f"Needs review: {summary['test_cases_needs_review']} | "
     f"Blocked: {summary['test_cases_blocked']} | "
     f"Not applicable: {summary['test_cases_not_applicable']}"
    ),
    f"Unassigned tests: {summary['unassigned_test_cases']}",
   ]

   for category in data["test_plan"]:
    category_lines.append(
     f"{category['category']}: "
     f"{category['completed']}/{category['applicable']} "
     f"({category['completion_percent']}%) — {category['status']} | "
     f"Review: {category['needs_review']} | "
     f"Blocked: {category['blocked']}"
    )

   category_lines = endpoint_lines + category_lines
   category_lines.extend(["", data["notice"]])
   self.coverage_notice.setText("\\n".join(category_lines))

  except Exception as exc:
   self.db.rollback()
   self.coverage_summary.setText("Could not load coverage.")
   self.coverage_asset_list.addItem(str(exc))
   self.coverage_notice.clear()

 def refresh_all(self):
  self.refresh_overview()
  self.refresh_activity()
  self.refresh_checks()
  self.refresh_coverage_view()
  self.refresh_workflow_views()
  if self.project_id:
   self.refresh_scope()
   self.refresh_findings()
   project=self.db.get(Project,self.project_id)
   if project:
    self.testing_project_label.setText(
     f"Selected project: {project.name} | Scope approved: {project.scope_approved}"
    )
  else:
   self.testing_project_label.setText("Selected project: none")
  self.refresh_evidence_jobs()
  self.refresh_passive_candidates()

 def refresh_passive_candidates(self):
  if not hasattr(self,"passive_candidate_list"):
   return
  self.passive_candidate_list.clear()
  if not self.project_id:
   self.passive_candidate_list.addItem("Select a project.")
   return

  candidates=self.db.scalars(
   select(ScopeAsset).where(
    ScopeAsset.project_id==self.project_id,
    ScopeAsset.included.is_(False),
    ScopeAsset.approved.is_(False),
   ).order_by(ScopeAsset.host.asc())
  ).all()

  visible=0
  for asset in candidates:
   if (asset.notes or "").startswith("REJECTED:"):
    continue
   item=QListWidgetItem(f"{asset.host}  |  UNAPPROVED CANDIDATE")
   item.setData(Qt.UserRole,asset.id)
   self.passive_candidate_list.addItem(item)
   visible+=1

  if not visible:
   self.passive_candidate_list.addItem("No unreviewed candidates.")

 def start_passive_recon_ui(self):
  try:
   self.require_project()
   project=self.db.get(Project,self.project_id)
   if not project or not project.scope_approved:
    raise ValueError("Approve the project's existing scope before passive reconnaissance.")

   if self.passive_recon_worker is not None and self.passive_recon_worker.isRunning():
    QMessageBox.information(self,"Passive recon","A passive reconnaissance job is already running.")
    return

   answer=QMessageBox.question(
    self,
    "Confirm passive reconnaissance",
    "This will resolve approved hostnames using local DNS and query crt.sh "
    "for certificate records. It will not send HTTP requests to target hosts. "
    "New discoveries remain unapproved. Continue?",
    QMessageBox.Yes|QMessageBox.No
   )
   if answer!=QMessageBox.Yes:
    return

   job=create_job(self.db,self.project_id,"Passive reconnaissance")
   worker=PassiveReconWorker(
    job.id,self.project_id,
    use_certificate_transparency=True,
    delay_seconds=1.0,
    owner_id=self.user_id,
    parent=self,
   )
   worker.progress.connect(self.update_passive_recon_progress)
   worker.result_ready.connect(self.passive_recon_result)
   worker.error_occurred.connect(self.passive_recon_error)
   worker.finished.connect(self.passive_recon_finished)

   self.passive_recon_worker=worker
   self.passive_progress.setValue(0)
   self.passive_status.setText(f"Starting passive reconnaissance — job #{job.id}")
   self.passive_start_button.setEnabled(False)
   self.passive_stop_button.setEnabled(True)
   self.refresh_evidence_jobs()
   worker.start()
  except Exception as e:
   self.db.rollback()
   QMessageBox.warning(self,"Passive reconnaissance",str(e))

 def stop_passive_recon_ui(self):
  worker=self.passive_recon_worker
  if worker is None or not worker.isRunning():
   return
  worker.request_stop()
  self.passive_stop_button.setEnabled(False)
  self.passive_status.setText(
   "Stop requested. Waiting for the current DNS or CT operation to finish."
  )

 def update_passive_recon_progress(self,percent,message):
  self.passive_progress.setValue(percent)
  self.passive_status.setText(message)

 def passive_recon_result(self,result):
  self.refresh_all()
  warnings=result.get("errors") or []

  if result.get("stopped"):
   state="stopped safely"
  elif warnings:
   state="completed with warnings"
  else:
   state="completed"

  self.passive_status.setText(
   f"Passive reconnaissance {state}. "
   f"New unapproved candidates: {len(result.get('new_candidates',[]))}."
  )

  warning_details="\n".join(
   f"- {str(item)[:500]}" for item in warnings[:5]
  )
  warning_section=(
   f"Warnings: {len(warnings)}\n{warning_details}\n\n"
   if warnings else "Warnings: 0\n\n"
  )

  QMessageBox.information(
   self,"Passive reconnaissance",
   f"Status: {state}\n"
   f"Approved assets processed: {len(result.get('dns',{}))}\n"
   f"CT requests: {result.get('ct_requests',0)}\n"
   f"Certificate names: {len(result.get('certificate_names',[]))}\n"
   f"New unapproved candidates: {len(result.get('new_candidates',[]))}\n"
   f"Requests sent to target hosts: 0\n\n"
   f"{warning_section}"
   "Review every candidate against the programme policy before approving it."
  )

 def passive_recon_error(self,message):
  self.refresh_all()
  self.passive_status.setText("Passive reconnaissance failed.")
  QMessageBox.warning(self,"Passive reconnaissance failed",message)

 def passive_recon_finished(self):
  self.passive_start_button.setEnabled(True)
  self.passive_stop_button.setEnabled(False)
  self.passive_recon_worker=None
  self.refresh_evidence_jobs()
  self.refresh_passive_candidates()


  def review_passive_candidate(self, approve):
      try:
          self.require_project()
          item = self.passive_candidate_list.currentItem()

          if not item or not item.data(Qt.UserRole):
              raise ValueError("Select a discovered candidate first.")

          asset = self.db.get(ScopeAsset, item.data(Qt.UserRole))
          if not asset or asset.project_id != self.project_id:
              raise ValueError("Candidate not found in the selected project.")

          if asset.included or asset.approved:
              raise ValueError("This asset is no longer an unapproved candidate.")

          if (asset.notes or "").startswith("REJECTED:"):
              raise ValueError("This candidate was already rejected.")

          if approve:
              answer = QMessageBox.warning(
                  self,
                  "Explicit scope review required",
                  f"Candidate: {asset.host}\\n\\n"
                  "Have you personally checked the current programme policy "
                  "and verified that this exact hostname is explicitly in scope?\\n\\n"
                  "Adding this candidate revokes the project's existing "
                  "scope approval. The complete scope must be reviewed again.",
                  QMessageBox.Yes | QMessageBox.No
              )
              if answer != QMessageBox.Yes:
                  return

              project = self.db.get(Project, self.project_id)
              if not project:
                  raise ValueError("Selected project was not found.")

              all_assets = self.db.scalars(
                  select(ScopeAsset).where(
                      ScopeAsset.project_id == self.project_id
                  )
              ).all()

              for registered_asset in all_assets:
                  registered_asset.approved = False

              asset.included = True
              asset.approved = False
              asset.notes = (asset.notes or "") + (
                  "\\nManually added to included scope after programme-policy "
                  "review. Project-wide approval revoked; full scope "
                  "reapproval required."
              )

              project.scope_approved = False
              project.status = "draft"

              self.db.commit()

              log_activity(
                  self.db,
                  self.project_id,
                  "Scope changed; previous approval revoked",
                  f"Discovered candidate {asset.host} added to included scope. "
                  "All asset approvals revoked pending full scope reapproval."
              )

              QMessageBox.information(
                  self,
                  "Candidate added — reapproval required",
                  f"{asset.host} was added to included scope, but is NOT "
                  "approved. Review the complete updated scope and use "
                  "APPROVE SCOPE before starting another assessment."
              )

          else:
              answer = QMessageBox.question(
                  self,
                  "Reject candidate",
                  f"Mark {asset.host} as rejected? "
                  "It will remain in the database for audit history.",
                  QMessageBox.Yes | QMessageBox.No
              )
              if answer != QMessageBox.Yes:
                  return

              asset.notes = "REJECTED: " + (asset.notes or "")
              log_activity(
                  self.db,
                  self.project_id,
                  "Discovered scope candidate rejected",
                  asset.host
              )

              QMessageBox.information(
                  self,
                  "Candidate rejected",
                  f"{asset.host} was marked rejected. Its record was retained."
              )

          self.db.commit()
          self.refresh_all()

      except Exception as e:
          self.db.rollback()
          QMessageBox.warning(self, "Candidate review", str(e))
 def add_endpoint_ui(self):
  try:
   self.require_project()
   project=self.db.get(Project,self.project_id)
   if not project or not project.scope_approved:
    raise ValueError("Approve project scope before registering endpoints.")

   url,ok=QInputDialog.getText(
    self,"Add endpoint","Complete URL belonging to an approved host:"
   )
   if not ok or not url.strip():
    return

   types=[
    "Web page","API endpoint","Login","Registration",
    "Password recovery","File upload","Admin function","Other"
   ]
   endpoint_type,ok=QInputDialog.getItem(
    self,"Endpoint type","Classify endpoint:",types,0,False
   )
   if not ok:
    return

   methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"]
   method,ok=QInputDialog.getItem(
    self,"HTTP method","Method:",methods,0,False
   )
   if not ok:
    return

   notes,ok=QInputDialog.getMultiLineText(
    self,"Endpoint notes","Purpose, parameters, roles or discovery source:"
   )
   if not ok:
    return

   endpoint=add_endpoint(
    self.db,self.project_id,url,endpoint_type,method,notes
   )
   self.refresh_workflow_views()
   QMessageBox.information(
    self,"Endpoint saved",
    f"Endpoint #{endpoint.id} registered. No network request was sent."
   )
  except Exception as e:
   self.db.rollback()
   QMessageBox.warning(self,"Endpoint",str(e))

 def generate_endpoint_tests_ui(self):
  try:
   self.require_project()

   project=self.db.get(Project,self.project_id)
   if not project or not project.scope_approved:
    raise ValueError(
     "Approve this project's scope before generating endpoint tests."
    )

   created=recommend_endpoint_tests(
    self.db,self.project_id
   )
   self.db.commit()

   self.refresh_workflow_views()
   self.refresh_coverage_view()

   if created:
    QMessageBox.information(
     self,"Endpoint assessments generated",
     f"Created {created} new endpoint-specific manual assessment tasks.\\n\\n"
     "Existing tasks and their statuses were preserved. "
     "No target requests or payloads were sent."
    )
   else:
    QMessageBox.information(
     self,"No new assessments",
     "No new recommendations were needed. Existing recommendations "
     "were preserved, or the registered endpoints have no matching "
     "recommendations.\\n\\nNo target requests were sent."
    )

  except Exception as e:
   self.db.rollback()
   QMessageBox.warning(
    self,"Endpoint assessment planner",str(e)
   )

 def refresh_project_intelligence(self):
  """Display readable, read-only project intelligence."""
  if not hasattr(self, "project_intelligence_list"):
   return

  self.project_intelligence_list.clear()

  if not self.project_id:
   self.project_intelligence_list.addItem("Select a project first.")
   return

  try:
   from app.services.project_intelligence import get_project_intelligence

   data = get_project_intelligence(self.db, self.project_id)

   if not isinstance(data, dict) or not data:
    self.project_intelligence_list.addItem(
     "No project intelligence data is available yet."
    )
    return

   inventory = data.get("inventory", {})
   assessment = data.get("assessment", {})
   summary = assessment.get("summary", {})
   findings = data.get("finding_summary", {})
   resources = data.get("resource_summary", {})
   duplicates = data.get("duplicate_review", {})
   integrity = data.get("integrity", {})

   add = self.project_intelligence_list.addItem

   add("PROJECT INVENTORY")
   add(f"Endpoints: {inventory.get('endpoints', 0)}")
   add(f"Test cases: {inventory.get('test_cases', 0)}")
   add(f"Findings: {inventory.get('findings', 0)}")

   add("")
   add("ASSESSMENT PROGRESS")
   add(f"Recommendations: {summary.get('recommendations', 0)}")
   add(f"Completed: {summary.get('completed', 0)}")
   add(f"Applicable: {summary.get('applicable', 0)}")
   add(f"Completion: {summary.get('completion_percent', 0)}%")

   add("")
   add("ENDPOINT-SPECIFIC ASSESSMENTS")

   endpoint_rows = assessment.get("endpoints", [])
   if not endpoint_rows:
    add("No endpoint recommendations available.")

   for endpoint in endpoint_rows:
    method = endpoint.get("method", "GET")
    url = endpoint.get("url", "")
    priority = endpoint.get("priority_band", "Unclassified")
    recommendations = endpoint.get("recommendations", [])

    add("")
    add(f"{method} {url}")
    add(
     f"Priority: {priority} | "
     f"Recommendations: {len(recommendations)} | "
     f"Progress: {endpoint.get('assessment_percent', 0)}%"
    )

    for item in recommendations:
     add(
      f"  [{item.get('status', 'Planned')}] "
      f"{item.get('category', 'General')}: "
      f"{item.get('title', 'Assessment task')}"
     )

   add("")
   add("API RESOURCE COVERAGE")
   add(f"Resource groups: {resources.get('resource_groups', 0)}")
   add(f"API resource endpoints: {resources.get('api_resource_endpoints', 0)}")
   add(
    f"Endpoints with recommendations: "
    f"{resources.get('endpoints_with_recommendations', 0)}"
   )
   add(
    f"Endpoints without recommendations: "
    f"{resources.get('endpoints_without_recommendations', 0)}"
   )

   add("")
   add("FINDING REVIEW")
   add(f"Total findings: {findings.get('total', 0)}")
   add(f"Potential findings: {findings.get('potential', 0)}")
   add(
    f"Confirmed or verified: "
    f"{findings.get('confirmed_or_verified', 0)}"
   )
   add(f"Exact duplicate groups: {duplicates.get('exact_group_count', 0)}")
   add(f"Possible duplicate pairs: {duplicates.get('possible_pair_count', 0)}")

   add("")
   add("SAFETY AND INTEGRITY")
   add(f"Read-only analysis: {integrity.get('read_only', False)}")
   add(
    f"Automatic finding confirmation: "
    f"{integrity.get('automatic_finding_confirmation', False)}"
   )
   add(
    f"Automatic duplicate merges: "
    f"{integrity.get('automatic_duplicate_merges', 0)}"
   )
   add(f"Network requests made: {integrity.get('network_requests_made', 0)}")
   add(f"Payloads executed: {integrity.get('payloads_executed', 0)}")
   add("Human review is required before findings are confirmed.")

   self.statusBar().showMessage("Project intelligence refreshed.", 5000)

  except Exception as e:
   self.project_intelligence_list.clear()
   self.project_intelligence_list.addItem(
    "Could not load project intelligence: " + str(e)
   )


 def refresh_workflow_views(self):
  if not hasattr(self,"endpoint_list"):
   return

  self.endpoint_list.clear()
  self.test_case_list.clear()
  self.api_resource_list.clear()

  if not self.project_id:
   self.endpoint_list.addItem("Select a project first.")
   self.api_resource_list.addItem("Select a project first.")
   self.test_case_list.addItem("Select a project first.")
   return

  endpoints=self.db.scalars(
   select(Endpoint)
   .where(Endpoint.project_id==self.project_id)
   .order_by(Endpoint.id.desc())
  ).all()

  coverage_data = get_project_coverage(
   self.db, self.project_id
  )
  endpoint_coverage = {
   item["endpoint_id"]: item
   for item in coverage_data["endpoints"]
  }

  if endpoints:
   for endpoint in endpoints:
    coverage = endpoint_coverage.get(endpoint.id, {})
    if coverage.get("has_recommendations"):
     coverage_label = (
      f"{coverage['completed']}/{coverage['applicable']} completed"
      f" | {coverage['needs_review']} review"
      f" | {coverage['planned']} planned"
      f" | {coverage['completion_percent']}%"
     )
    else:
     coverage_label = "No endpoint tests recommended yet"

    priority = coverage.get("priority_band", "Not classified")
    score = coverage.get("priority_score", 0)
    display_url = coverage.get("display_url", endpoint.url)

    item=QListWidgetItem(
     f"#{endpoint.id} | {endpoint.method} | "
     f"{endpoint.endpoint_type} | {priority} ({score}/100)\n"
     f"{display_url}\n"
     f"Assessment: {coverage_label}"
    )
    item.setData(Qt.UserRole,endpoint.id)
    self.endpoint_list.addItem(item)
  else:
   self.endpoint_list.addItem("No endpoints registered yet.")

  resource_groups = coverage_data.get("api_resource_groups", [])
  if resource_groups:
   for group in resource_groups:
    methods = ", ".join(group.get("methods", [])) or "None"
    collection = ", ".join(
     group.get("collection_methods", [])
    ) or "None"
    item_methods = ", ".join(
     group.get("item_methods", [])
    ) or "None"
    identifiers = ", ".join(
     group.get("identifier_parameters", [])
    ) or "None detected"

    missing = group.get("not_observed", [])
    missing_text = ", ".join(
     f"{entry['method']} ({entry['route_type']})"
     for entry in missing
    ) or "No suggested gaps"

    parent = group.get("parent_resource") or "Root resource"

    lines = [
     f"{group['resource_path']}",
     f"Observed methods: {methods}",
     f"Collection: {collection} | Individual: {item_methods}",
     f"Endpoints: {group['endpoint_count']} | Parent: {parent}",
     f"Assessment progress: {group.get('assessment_summary', 'No tasks recorded')}",
     f"Authorization progress: {group.get('authorization_summary', 'No authorization tasks recorded')}",
     f"Assessment tasks: {group.get('assessment_task_count', 0)}",
     f"Identifiers: {identifiers}",
     "Authorization review: "
     + (
         "; ".join(group.get("authorization_review_signals", []))
         or "No specific relationship signals detected"
     ),
     f"Not observed; review if applicable: {missing_text}",
    ]

    for route in group.get("routes", []):
     lines.append(
      f"  #{route['endpoint_id']} "
      f"{route['method']} {route['path']} | "
      f"Assessment: {route.get('assessment_summary', 'No tasks recorded')} | "
      f"Authorization: {route.get('authorization_summary', 'No tasks recorded')}"
     )
     for scenario in route.get("assessment_scenarios", []):
      lines.append(
       f"    [{scenario['review_priority']}] "
       f"{scenario['category']}: {scenario['title']} "
       f"| {scenario['status']}"
      )

    lines.append(
     "Coverage is URL-based; routes sharing a URL may share task counts."
    )
    lines.append(
     "'Finding identified' requires evidence-based review."
    )
    item = QListWidgetItem("\n".join(lines))
    item.setData(Qt.UserRole, group["resource_path"])
    self.api_resource_list.addItem(item)
  else:
   self.api_resource_list.addItem(
    "No API resource groups identified yet. "
    "Discover or register API endpoints to build this map."
   )

  tests=self.db.scalars(
   select(TestCase)
   .where(TestCase.project_id==self.project_id)
   .order_by(TestCase.category,TestCase.id)
  ).all()

  if tests:
   for test in tests:
    item=QListWidgetItem(
     f"[{test.status}] {test.category} — {test.title}"
     + (f" | {test.target}" if test.target else "")
    )
    item.setData(Qt.UserRole,test.id)
    self.test_case_list.addItem(item)
  else:
   self.test_case_list.addItem(
    "No test plan yet. Select INITIALIZE TEST PLAN."
   )

  self.show_test_case_details(
   self.test_case_list.currentItem(), None
  )

 def show_test_case_details(self, current=None, previous=None):
  if not hasattr(self, "test_case_details"):
   return

  if not current or not current.data(Qt.UserRole):
   self.test_case_details.setPlainText(
    "Select a test case to view its assessment worksheet and evidence."
   )
   return

  test=self.db.get(TestCase,current.data(Qt.UserRole))
  if not test or test.project_id!=self.project_id:
   self.test_case_details.setPlainText(
    "The selected test case is unavailable in this project."
   )
   return

  notes = test.notes or "No observations recorded yet."
  has_worksheet = "MANUAL ASSESSMENT WORKSHEET" in notes
  history = assessment_history(test)

  visible_notes = notes.split(
   "ASSESSMENT_RESULT_HISTORY:", 1
  )[0].rstrip()

  history_lines = []
  for record in history[-10:]:
   history_lines.extend([
    f"DATE: {record.get('recorded_at', 'Unknown')}",
    f"STATUS: {record.get('status', 'Unknown')}",
    f"EXPECTED: {record.get('expected_behavior', '') or 'Not recorded'}",
    f"OBSERVED: {record.get('observed_behavior', '') or 'Not recorded'}",
    f"EVIDENCE: {record.get('evidence_reference', '') or 'Not supplied'}",
    f"LIMITATIONS: {record.get('limitations', '') or 'None recorded'}",
    f"REVIEWER: {record.get('reviewer', '') or 'Not recorded'}",
    ""
   ])

  sections = [
   f"TEST: {test.title}",
   f"CATEGORY: {test.category}",
   f"STATUS: {test.status}",
   f"TARGET: {test.target or 'Not assigned'}",
   "",
   "WORKSHEET:",
   (
    "Structured manual worksheet available. Use UPDATE SELECTED TEST "
    "to record expected behavior, observations and evidence."
    if has_worksheet else
    "No structured worksheet attached. Record methodology, expected "
    "behavior, observations, evidence and limitations."
   ),
   "",
   "ASSESSMENT NOTES / WORKSHEET:",
   visible_notes or "No additional notes.",
   "",
   "STRUCTURED ASSESSMENT HISTORY:",
   "\\n".join(history_lines) if history_lines else
   "No structured assessment submissions yet.",
   "",
   "ASSESSMENT GUIDANCE:",
   "- Use only explicitly approved targets and authorized test accounts.",
   "- Redact credentials, tokens and personal data from evidence.",
   "- Record expected and observed behavior separately.",
   "- A recommendation or planned check is not proof of a vulnerability.",
   "- Potential findings require independent verification.",
  ]

  self.test_case_details.setPlainText("\\n".join(sections))

 def initialize_plan_ui(self):
  try:
   self.require_project()
   project=self.db.get(Project,self.project_id)
   if not project or not project.scope_approved:
    raise ValueError("Approve project scope before starting the project test plan.")

   count=initialize_test_plan(self.db,self.project_id)
   self.refresh_workflow_views()

   if count:
    QMessageBox.information(
     self,"Test plan",f"{count} OWASP-aligned test cases created."
    )
   else:
    QMessageBox.information(
     self,"Test plan","A test plan already exists for this project."
    )
  except Exception as e:
   self.db.rollback()
   QMessageBox.warning(self,"Test plan",str(e))

 def update_test_ui(self):
  try:
   self.require_project()
   item=self.test_case_list.currentItem()
   if not item or not item.data(Qt.UserRole):
    raise ValueError("Select a test case first.")

   test=self.db.get(TestCase,item.data(Qt.UserRole))
   if not test or test.project_id!=self.project_id:
    raise ValueError("Test case not found.")

   statuses=[
    "Planned","In progress","Needs review",
    "Finding identified","Passed","Blocked","Not applicable"
   ]

   status,ok=QInputDialog.getItem(
    self,"Update test","Assessment status:",
    statuses,
    statuses.index(test.status) if test.status in statuses else 0,
    False
   )
   if not ok:
    return

   target,ok=QInputDialog.getText(
    self,"Test target","Optional complete URL in approved scope:",
    text=test.target or ""
   )
   if not ok:
    return

   editor_notes = test.notes or ""
   if "ASSESSMENT RESULT" not in editor_notes:
    editor_notes = (
     editor_notes.rstrip()
     + "\\n\\nASSESSMENT RESULT\\n"
     + "Expected behavior:\\n"
     + "Observed behavior:\\n"
     + "Evidence reference (redacted):\\n"
     + "Limitations:\\n"
    )

   notes,ok=QInputDialog.getMultiLineText(
    self,"Assessment worksheet and results",
    "Complete the ASSESSMENT RESULT section. Keep the worksheet "
    "and enter expected behavior, observed behavior, evidence "
    "reference and limitations:",
    editor_notes
   )
   if not ok:
    return

   # Extract structured fields from the existing worksheet format.
   labels = [
    "Expected behavior:",
    "Observed behavior:",
    "Evidence reference (redacted):",
    "Limitations:"
   ]

   result_section = (
    notes.split("ASSESSMENT RESULT", 1)[1]
    if "ASSESSMENT RESULT" in notes else ""
   )

   def extract_field(label):
    position = result_section.find(label)
    if position < 0:
     return ""

    value_start = position + len(label)
    following = [
     result_section.find(other, value_start)
     for other in labels
     if other != label
     and result_section.find(other, value_start) >= 0
    ]
    value_end = min(following) if following else len(result_section)
    return result_section[value_start:value_end].strip()

   expected = extract_field("Expected behavior:")
   observed = extract_field("Observed behavior:")
   evidence_ref = extract_field("Evidence reference (redacted):")
   limitations = extract_field("Limitations:")

   create_potential = False
   if status == "Finding identified" and observed:
    answer = QMessageBox.question(
     self,
     "Create potential finding?",
     "An observed behavior has been supplied. Create a low-confidence "
     "potential finding for human verification?\\n\\n"
     "This will NOT confirm a vulnerability.",
     QMessageBox.Yes | QMessageBox.No,
     QMessageBox.No
    )
    create_potential = answer == QMessageBox.Yes

   # Preserve the existing target when the optional field is left blank.
   target_value = target.strip() or test.target or ""

   # Existing workflow validates the target and saves the worksheet.
   update_test_case(
    self.db,self.project_id,test.id,status,target_value,notes,commit=False
   )

   # Record structured history and an auditable ScanCheck observation.
   result = record_assessment_result(
    self.db,
    test.id,
    status,
    expected,
    observed,
    evidence_ref,
    limitations,
    reviewer=self.username.text().strip() if hasattr(self, "username") else "",
    create_potential_finding=create_potential
   )
   self.db.commit()

   log_activity(
    self.db,
    self.project_id,
    "Structured assessment recorded",
    f"{test.title}: {status}; ScanCheck #{result['observation'].id}"
   )

   self.refresh_workflow_views()

   if create_potential and result["potential_finding"]:
    self.refresh_findings()
    message = (
     "Assessment and observation saved. Potential finding #"
     f"{result['potential_finding'].id} created. "
     "It remains unconfirmed and requires human verification."
    )
   elif status == "Finding identified" and not observed:
    message = (
     "Assessment saved, but no observed behavior was supplied. "
     "No potential finding was created."
    )
   else:
    message = (
     "Structured assessment history and observation saved successfully. "
     "No vulnerability was automatically confirmed."
    )

   QMessageBox.information(self,"Assessment saved",message)

  except Exception as e:
   self.db.rollback()
   QMessageBox.warning(self,"Test plan",str(e))

 def create_test_finding(self):
  try:
   self.require_project()
   item=self.test_case_list.currentItem()
   if not item or not item.data(Qt.UserRole):
    raise ValueError("Select a test case first.")

   test=self.db.get(TestCase,item.data(Qt.UserRole))
   if not test or test.project_id!=self.project_id:
    raise ValueError("Test case not found.")

   if test.status not in ("Finding identified","Needs review"):
    raise ValueError(
     "First update the test status to Finding identified or Needs review."
    )

   title,ok=QInputDialog.getText(
    self,"New potential finding","Finding title:",text=test.title
   )
   if not ok or not title.strip():
    return

   severities=["info","low","medium","high","critical"]
   severity,ok=QInputDialog.getItem(
    self,"Severity","Initial severity:",severities,1,False
   )
   if not ok:
    return

   finding=Finding(
    project_id=self.project_id,
    title=title.strip(),
    category=test.category,
    severity=severity,
    confidence="low",
    status="potential",
    asset=test.target,
    description=(
     "Created from a manual OWASP test-plan observation. "
     "Reproduction, impact and authorization require verification."
    ),
    evidence=test.notes,
    remediation="Document root cause and an appropriate remediation."
   )

   self.db.add(finding)
   self.db.commit()

   log_activity(
    self.db,self.project_id,
    "Potential finding created",title.strip()
   )

   self.refresh_findings()
   self.refresh_workflow_views()

   QMessageBox.information(
    self,"Finding created",
    "Potential finding saved. It has not been marked confirmed."
   )
  except Exception as e:
   self.db.rollback()
   QMessageBox.warning(self,"Finding",str(e))


 def refresh_evidence_jobs(self):
  if not hasattr(self,"evidence_list"):
   return

  self.evidence_list.clear()
  self.job_list.clear()

  if not self.project_id:
   self.evidence_list.addItem("Select a project.")
   self.job_list.addItem("Select a project.")
   return

  from app.models.entities import TestCase, ScanCheck

  for record in list_evidence(self.db,self.project_id):
   linked_finding=""
   if record.finding_id:
    linked=self.db.get(Finding,record.finding_id)
    if linked and linked.project_id==self.project_id:
     linked_finding=(
      f" | Linked to finding #{linked.id}: {linked.title}"
     )
    else:
     linked_finding=" | Finding link unavailable"

   linked_test = ""
   if record.test_case_id:
    test = self.db.get(TestCase, record.test_case_id)
    if test and test.project_id == self.project_id:
     linked_test = (
      f" | Assessment #{test.id}: {test.title} [{test.status}]"
     )
    else:
     linked_test = " | Assessment link unavailable"

   linked_observation = ""
   if record.scan_check_id:
    observation = self.db.get(ScanCheck, record.scan_check_id)
    if observation and observation.project_id == self.project_id:
     linked_observation = (
      f" | Observation #{observation.id}: "
      f"{observation.check_name} [{observation.outcome}]"
     )
    else:
     linked_observation = " | Observation link unavailable"

   item=QListWidgetItem(
    f"#{record.id} | {record.original_name} | "
    f"{record.size_bytes} bytes | "
    f"SHA256 {record.sha256[:16]}...{linked_finding}"
    f"{linked_test}{linked_observation}"
   )
   item.setData(Qt.UserRole,record.id)
   self.evidence_list.addItem(item)

  if not self.evidence_list.count():
   self.evidence_list.addItem("No evidence attached.")

  jobs=list_jobs(self.db,self.project_id)
  for job in jobs:
   item=QListWidgetItem(
    f"#{job.id} | {job.job_type} | {job.status.upper()} | "
    f"{job.progress}%"
   )
   item.setData(Qt.UserRole,job.id)
   self.job_list.addItem(item)

  if not self.job_list.count():
   self.job_list.addItem("No jobs recorded.")

  if hasattr(self,"website_progress"):
   hunts=[job for job in jobs if job.job_type=="Automated hunt"]
   latest=hunts[0] if hunts else None
   active=latest if latest and latest.status in {"queued","running"} else None
   self.start_website_button.setEnabled(active is None)
   self.stop_website_button.setEnabled(active is not None)
   if latest:
    self.website_progress.setValue(max(0,min(100,latest.progress)))
    checkpoint=(latest.checkpoint or "").strip()
    detail=f" — {checkpoint[:180]}" if checkpoint else ""
    self.website_status.setText(f"Hunt #{latest.id}: {latest.status.upper()} ({latest.progress}%)"+detail)
   else:
    self.website_status.setText("No automated hunt has been queued for this project.")

   snapshot=(latest.id,latest.status) if latest else None
   previous=self._last_hunt_snapshot
   self._last_hunt_snapshot=snapshot
   if (
    previous is not None
    and previous != snapshot
    and not self._refreshing_hunt_dashboard
   ):
    self._refreshing_hunt_dashboard=True
    try:
     self.refresh_all()
    finally:
     self._refreshing_hunt_dashboard=False

 def attach_evidence_ui(self):
  try:
   self.require_project()
   filename,_=QFileDialog.getOpenFileName(self,"Select evidence file")
   if not filename:
    return

   # Allow evidence to be linked to an assessment test.
   tests=self.db.scalars(
    select(TestCase)
    .where(TestCase.project_id==self.project_id)
    .order_by(TestCase.created_at.desc())
   ).all()

   test_case_id=None
   if tests:
    choices=["No assessment link"] + [
     f"#{test.id} | {test.title} | {test.status}"
     for test in tests
    ]
    selected_test,ok=QInputDialog.getItem(
     self,"Link assessment",
     "Associate this evidence with an assessment test:",
     choices,0,False
    )
    if not ok:
     return

    if selected_test!="No assessment link":
     for test in tests:
      if selected_test.startswith(f"#{test.id} |"):
       test_case_id=test.id
       break

   finding_id=None
   selected=self.finding_list.currentItem()
   selected_id=selected.data(Qt.UserRole) if selected else None

   if selected_id:
    selected_finding=self.db.get(Finding,int(selected_id))
    if (
     selected_finding
     and selected_finding.project_id==self.project_id
    ):
     answer=QMessageBox.question(
      self,
      "Link evidence",
      f"Link this evidence to finding #{selected_finding.id}: "
      f"{selected_finding.title}?",
      QMessageBox.Yes|QMessageBox.No
     )
     if answer==QMessageBox.Yes:
      finding_id=selected_finding.id

   notes,ok=QInputDialog.getMultiLineText(
    self,"Evidence notes","Describe this evidence:"
   )
   if not ok:
    return

   record=add_evidence(
    self.db,
    self.project_id,
    filename,
    notes,
    finding_id=finding_id,
    test_case_id=test_case_id
   )

   self.refresh_evidence_jobs()

   linked_test=(
    f"Assessment test: #{record.test_case_id}\n"
    if record.test_case_id else "Assessment test: Not linked\n"
   )
   linked_observation=(
    f"Observation: #{record.scan_check_id}\n"
    if record.scan_check_id else "Observation: No recorded observation linked\n"
   )

   QMessageBox.information(
    self,"Evidence saved",
    f"Evidence #{record.id}\n"
    f"{linked_test}{linked_observation}"
    f"SHA-256: {record.sha256}"
   )
  except Exception as e:
   self.db.rollback()
   QMessageBox.warning(self,"Evidence",str(e))

 def verify_evidence_ui(self):
  try:
   self.require_project()
   item=self.evidence_list.currentItem()
   if not item or not item.data(Qt.UserRole):
    raise ValueError("Select an evidence record.")

   record=self.db.get(Evidence,item.data(Qt.UserRole))
   if not record or record.project_id!=self.project_id:
    raise ValueError("Evidence record not found.")

   if verify_evidence(record):
    QMessageBox.information(
     self,"Verified",f"SHA-256 matches:\n{record.sha256}"
    )
   else:
    QMessageBox.warning(
     self,"Verification failed","File missing or hash mismatch."
    )
  except Exception as e:
   QMessageBox.warning(self,"Evidence",str(e))

 def audit_evidence_ui(self):
  try:
   self.require_project()
   result=audit_project_evidence(self.db,self.project_id)
   summary=result["summary"]

   lines=[
    f"Evidence records audited: {summary['total']}",
    f"Verified files: {summary['verified']}",
    f"Missing files: {summary['missing']}",
    f"Invalid paths: {summary['invalid_path']}",
    f"Size mismatches: {summary['size_mismatch']}",
    f"SHA-256 mismatches: {summary['hash_mismatch']}",
    f"Oversized files: {summary['oversized']}",
    f"Invalid metadata: {summary['invalid_metadata']}",
    f"Unreadable files: {summary['unreadable']}",
    f"Broken references: {summary['broken_reference']}",
    f"Unlinked evidence: {summary['unlinked']}",
    "",
    "Per-file results:",
   ]

   for entry in result["records"][:50]:
    lines.append(
     f"#{entry['id']} {entry['name']} — "
     f"file: {entry['file_integrity']} — "
     f"links: {entry['reference_integrity']}"
    )
    if entry["file_integrity"]!="verified":
     lines.append(f"  {entry['file_reason']}")
    if entry["reference_integrity"]=="broken_reference":
     lines.append(f"  {entry['reference_reason']}")

   remaining=len(result["records"])-50
   if remaining>0:
    lines.append(f"... and {remaining} more records.")

   message="\\n".join(lines)
   if (
    summary["verified"]==summary["total"]
    and summary["broken_reference"]==0
    and summary["unlinked"]==0
   ):
    QMessageBox.information(self,"Evidence audit",message)
   else:
    QMessageBox.warning(self,"Evidence audit",message)
  except Exception as e:
   QMessageBox.warning(self,"Evidence audit",str(e))

 def open_evidence_folder_ui(self):
  try:
   self.require_project()
   from app.services.evidence import evidence_directory
   folder=evidence_directory(self.project_id)
   QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))
  except Exception as e:
   QMessageBox.warning(self,"Evidence folder",str(e))

 def create_job_ui(self):
  try:
   self.require_project()
   project=self.db.get(Project,self.project_id)
   if not project or not project.scope_approved:
    raise ValueError("Approve project scope first.")

   choices=[
    "Manual assessment","Security header assessment",
    "Endpoint review","Evidence review","Report preparation"
   ]
   job_type,ok=QInputDialog.getItem(
    self,"Create job","Job type:",choices,0,False
   )
   if not ok:
    return

   job=create_job(self.db,self.project_id,job_type)
   self.refresh_evidence_jobs()
   QMessageBox.information(
    self,"Job created",
    f"Job #{job.id} queued. No network activity was started."
   )
  except Exception as e:
   self.db.rollback()
   QMessageBox.warning(self,"Job manager",str(e))

 def update_job_ui(self):
  try:
   self.require_project()
   item=self.job_list.currentItem()
   if not item or not item.data(Qt.UserRole):
    raise ValueError("Select a job.")

   job=self.db.get(AssessmentJob,int(item.data(Qt.UserRole)))
   if not job or job.project_id!=self.project_id:
    raise ValueError("Job not found in the selected project.")

   details=(
    f"Job: #{job.id}\\nType: {job.job_type}\\n"
    f"Status: {job.status.upper()}\\nProgress: {job.progress}%\\n"
    f"Created: {job.created_at}\\nUpdated: {job.updated_at}\\n"
    f"Started: {job.started_at or 'Not started'}\\n"
    f"Finished: {job.finished_at or 'Not finished'}\\n\\n"
    f"Checkpoint:\\n{job.checkpoint or 'None'}\\n\\n"
    f"Result summary:\\n{job.result_summary or 'None'}\\n\\n"
    f"Error:\\n{job.error_message or 'None'}"
   )

   if job.status == "queued":
    answer=QMessageBox.question(
     self,"Queued job",
     details + "\\n\\nCancel this queued job?",
     QMessageBox.Yes|QMessageBox.No,
     QMessageBox.No
    )
    if answer==QMessageBox.Yes:
     transition_job(
      self.db,job.id,"stopped",
      checkpoint="Cancelled by the user before a worker started.",
     )
     self.refresh_evidence_jobs()
     QMessageBox.information(
      self,"Job cancelled",
      f"Queued job #{job.id} was cancelled."
     )
    return

   extra=(
    "\\n\\nRunning jobs are controlled by their workers. "
    "Use the Stop button in the relevant assessment tab."
    if job.status == "running" else
    "\\n\\nThis job is not editable. Paused jobs cannot resume "
    "until checkpoint-based resume is implemented."
   )

   QMessageBox.information(self,"Job details",details+extra)

  except Exception as e:
   self.db.rollback()
   QMessageBox.warning(self,"Job manager",str(e))

 def require_project(self):
  if not self.project_id:
   raise ValueError("Select a project first.")

  project = self.db.get(Project, self.project_id)
  if not project:
   raise ValueError("The selected project no longer exists.")

  if project.status == "deleted":
   raise ValueError(
    "This project is archived and read-only. Restore it before making changes."
   )

  return project
 def new_project(self):
  try: p=create_project(self.db,self.pname.text(),self.purl.text()); self.refresh_projects(); self.refresh_all(); QMessageBox.information(self,"Project",f"Created project #{p.id}.")
  except Exception as e: QMessageBox.warning(self,"Project",str(e))
 def refresh_projects(self):
  self.project_list.clear()
  self.archived_project_list.clear()

  projects=self.db.scalars(
   select(Project)
   .where(Project.status != "deleted")
   .order_by(Project.id.desc())
  ).all()

  for p in projects:
   item=QListWidgetItem(
    f"{p.id} — {p.name} [{p.status}]"
   )
   item.setData(Qt.UserRole,p.id)
   self.project_list.addItem(item)

  archived=self.db.scalars(
   select(Project)
   .where(Project.status == "deleted")
   .order_by(Project.id.desc())
  ).all()

  for p in archived:
   item=QListWidgetItem(
    f"{p.id} — {p.name} [ARCHIVED]"
   )
   item.setData(Qt.UserRole,p.id)
   self.archived_project_list.addItem(item)

  self.archived_project_details.clear()

 def show_archived_project(self, item):
  try:
   project_id = item.data(Qt.UserRole)
   project = self.db.get(Project, int(project_id))

   if not project or project.status != "deleted":
    raise ValueError("Archived project not found.")

   scope_assets = self.db.scalars(
    select(ScopeAsset)
    .where(ScopeAsset.project_id == project.id)
    .order_by(ScopeAsset.host)
   ).all()

   activities = self.db.scalars(
    select(Activity)
    .where(Activity.project_id == project.id)
    .order_by(Activity.id.desc())
    .limit(10)
   ).all()

   finding_count = self.db.scalar(
    select(func.count()).select_from(Finding)
    .where(Finding.project_id == project.id)
   ) or 0

   evidence_count = self.db.scalar(
    select(func.count()).select_from(Evidence)
    .where(Evidence.project_id == project.id)
   ) or 0

   activity_count = self.db.scalar(
    select(func.count()).select_from(Activity)
    .where(Activity.project_id == project.id)
   ) or 0

   scope_text = "\n".join(
    f"- {asset.host} | included={asset.included} | "
    f"approved={asset.approved}"
    for asset in scope_assets
   ) or "No scope assets recorded."

   # Display event metadata only; never expose raw activity details.
   history_text = "\n".join(
    f"- {event.created_at} | {event.event}"
    for event in activities
   ) or "No activity history recorded."

   details = (
    f"ARCHIVED PROJECT #{project.id}\n"
    f"Name: {project.name}\n"
    f"Programme URL: {project.programme_url or 'Not recorded'}\n"
    f"Status: {project.status}\n"
    f"Scope approved: {project.scope_approved}\n\n"
    f"RETAINED RECORDS\n"
    f"Findings: {finding_count}\n"
    f"Evidence records: {evidence_count}\n"
    f"Activity entries: {activity_count}\n\n"
    f"SCOPE ASSETS\n{scope_text}\n\n"
    f"RECENT ACTIVITY (up to 10 entries)\n{history_text}\n\n"
    "READ-ONLY ARCHIVE: This project cannot be selected for scanning. "
    "Evidence files and historical records have not been modified."
   )

   self.archived_project_details.setPlainText(details)

  except Exception as e:
   self.db.rollback()
   QMessageBox.warning(self, "Archived project", str(e))


 def view_archived_project_records_ui(self):
  try:
   item = self.archived_project_list.currentItem()

   if item is None:
    raise ValueError("Select an archived project first.")

   project_id = int(item.data(Qt.UserRole))
   project = self.db.get(Project, project_id)

   if not project or project.status != "deleted":
    raise ValueError("Archived project not found.")

   findings = self.db.scalars(
    select(Finding)
    .where(Finding.project_id == project_id)
    .order_by(Finding.id.desc())
    .limit(50)
   ).all()

   lines = [
    f"ARCHIVED PROJECT #{project.id}: {project.name}",
    "READ ONLY — no project records will be changed.",
    "",
    f"Findings shown: {len(findings)} (maximum 50)",
    ""
   ]

   for finding in findings:
    lines.extend([
     f"FINDING #{finding.id}: {finding.title}",
     f"Category: {finding.category}",
     f"Severity: {finding.severity}",
     f"Confidence: {finding.confidence}",
     f"Status: {finding.status}",
     f"Asset: {finding.asset or 'Not recorded'}"
    ])

    reviews = self.db.scalars(
     select(FindingReview)
     .where(
      FindingReview.project_id == project_id,
      FindingReview.finding_id == finding.id
     )
     .order_by(
      FindingReview.created_at.desc(),
      FindingReview.id.desc()
     )
     .limit(10)
    ).all()

    lines.append("Review history:")
    if not reviews:
     lines.append("  No structured review records.")
    else:
     for review in reviews:
      lines.extend([
       f"  Review #{review.id} | {review.created_at}",
       f"  Reviewer: {review.reviewer}",
       f"  Status: {review.previous_status} -> {review.new_status}",
       f"  Severity: {review.previous_severity} -> {review.new_severity}",
       f"  Confidence: {review.previous_confidence} -> {review.new_confidence}"
      ])

    lines.extend(["", "-" * 55, ""])

   if not findings:
    lines.append("No findings have been recorded for this project.")

   QMessageBox.information(
    self,
    "Archived findings and review history",
    "\\n".join(lines)
   )

  except Exception as e:
   self.db.rollback()
   QMessageBox.warning(self, "Archived findings", str(e))


 def export_archived_project_ui(self):
  try:
   from app.core.config import DATA_DIR
   item = self.archived_project_list.currentItem()

   if item is None:
    raise ValueError("Select an archived project first.")

   project_id = int(item.data(Qt.UserRole))
   project = self.db.get(Project, project_id)

   if not project or project.status != "deleted":
    raise ValueError("Archived project not found.")

   from pathlib import Path

   report_dir = DATA_DIR / "reports" / f"account_{self.user_id}" / f"project_{project_id}"
   report_dir.mkdir(parents=True, exist_ok=True)

   path, _ = QFileDialog.getSaveFileName(
    self,
    "Export archived project report",
    str(report_dir / "archived-project-report.json"),
    "JSON (*.json);;Markdown (*.md);;HTML (*.html);;PDF (*.pdf);;Word Document (*.docx)"
   )

   if not path:
    return

   fmt = path.rsplit(".", 1)[-1].lower()
   fmt = {"md": "markdown"}.get(fmt, fmt)

   saved = export_report(self.db, project_id, path, fmt)

   QMessageBox.information(
    self,
    "Archived report exported",
    f"Read-only archived project report saved:\\n{saved}"
   )

  except Exception as e:
   self.db.rollback()
   QMessageBox.warning(self, "Archived report export", str(e))


 def restore_archived_project_ui(self):
  try:
   item = self.archived_project_list.currentItem()

   if item is None:
    raise ValueError("Select an archived project first.")

   project_id = int(item.data(Qt.UserRole))
   project = self.db.get(Project, project_id)

   if not project or project.status != "deleted":
    raise ValueError("Archived project not found.")

   answer = QMessageBox.warning(
    self,
    "Restore archived project",
    f"Restore project: {project.name}?\\n\\n"
    "The project will return as a DRAFT.\\n"
    "All previous scope approvals will be revoked.\\n"
    "You must review and approve its scope again before scanning.\\n\\n"
    "Historical findings and evidence will be retained.",
    QMessageBox.Yes | QMessageBox.No,
    QMessageBox.No
   )

   if answer != QMessageBox.Yes:
    return

   confirmation, ok = QInputDialog.getText(
    self,
    "Confirm project restoration",
    f"Type the exact project name to confirm:\\n{project.name}"
   )

   if not ok:
    return

   restored = restore_project(
    self.db,
    project_id,
    confirmation
   )

   self.refresh_projects()
   self.refresh_all()

   QMessageBox.information(
    self,
    "Project restored",
    f"{restored.name} has been restored as a draft.\\n\\n"
    "Review its scope and approve it again before starting any assessment."
   )

  except Exception as e:
   self.db.rollback()
   QMessageBox.warning(self, "Restore project", str(e))

 def delete_project_ui(self):
  try:
   self.require_project()

   passive=self.passive_recon_worker
   analysis=self.analysis_worker

   if passive is not None and passive.isRunning():
    raise ValueError(
     "Stop passive reconnaissance and wait for it to finish before deleting this project."
    )

   if analysis is not None and analysis.isRunning():
    raise ValueError(
     "Stop website analysis and wait for it to finish before deleting this project."
    )

   project=self.db.get(Project,self.project_id)

   if not project or project.status == "deleted":
    raise ValueError("Active project not found.")

   answer=QMessageBox.warning(
    self,
    "Retire project",
    f"Retire project: {project.name}?\n\n"
    "The project will disappear from the active project list.\n"
    "Findings, evidence files, evidence records and related history "
    "will be retained.\n\n"
    "This action cannot be undone from this interface.",
    QMessageBox.Yes | QMessageBox.No,
    QMessageBox.No
   )

   if answer != QMessageBox.Yes:
    return

   confirmation,ok=QInputDialog.getText(
    self,
    "Confirm project retirement",
    f"Type the exact project name to confirm:\n{project.name}"
   )

   if not ok:
    return

   delete_project(
    self.db,
    self.project_id,
    confirmation
   )

   self.project_id=None
   self.refresh_projects()
   self.refresh_all()
   self.refresh_workflow_views()
   self.refresh_scope()

   self.statusBar().showMessage(
    "Project retired. Historical records and evidence retained."
   )

   QMessageBox.information(
    self,
    "Project retired",
    "Project successfully retired.\n\n"
    "Its evidence and historical records have been preserved."
   )

  except Exception as e:
   self.db.rollback()
   QMessageBox.warning(self,"Delete project",str(e))

 def select_project(self,item):
  project_id=item.data(Qt.UserRole)
  if not project_id:
   return

  project=self.db.get(Project,int(project_id))
  if not project or project.status=="deleted":
   QMessageBox.warning(
    self,"Project selection",
    "This project is unavailable or has been retired."
   )
   self.refresh_projects()
   return

  self.project_id=project.id
  self.refresh_all()
  self.refresh_workflow_views()
  self.statusBar().showMessage(
   f"Selected project #{self.project_id}: {project.name}"
  )
 def refresh_scope(self):
  self.scope_list.clear(); p=self.db.get(Project,self.project_id)
  if p:
   for a in p.assets: self.scope_list.addItem(f"{a.host} | included={a.included} | approved={a.approved}")
   self.policy.setPlainText(p.policy_text or "")
 def create_finding_ui(self):
  try:
   self.require_project()
   project=self.db.get(Project,self.project_id)
   if not project or not project.scope_approved:
    raise ValueError("Approve the project scope before recording a finding.")

   title,ok=QInputDialog.getText(
    self,"Create finding","Finding title:"
   )
   if not ok or not title.strip():
    return

   categories=[
    "Access Control","Authentication","Injection","XSS",
    "SSRF","Security Misconfiguration","Information Disclosure",
    "Cryptography","Business Logic","API Security","Other"
   ]
   category,ok=QInputDialog.getItem(
    self,"Finding category","Category:",categories,0,False
   )
   if not ok:
    return

   severities=["info","low","medium","high","critical"]
   severity,ok=QInputDialog.getItem(
    self,"Finding severity","Initial severity:",severities,1,False
   )
   if not ok:
    return

   asset,ok=QInputDialog.getText(
    self,"Affected asset","Approved hostname or endpoint:"
   )
   if not ok:
    return

   description,ok=QInputDialog.getMultiLineText(
    self,"Technical description","Describe the behavior and security impact:"
   )
   if not ok:
    return

   evidence,ok=QInputDialog.getMultiLineText(
    self,"Evidence and reproduction","Record safe reproduction steps and observed evidence:"
   )
   if not ok:
    return

   remediation,ok=QInputDialog.getMultiLineText(
    self,"Remediation","Recommended fix or mitigation:"
   )
   if not ok:
    return

   finding=Finding(
    project_id=self.project_id,
    title=title.strip(),
    category=category,
    severity=severity,
    confidence="low",
    status="potential",
    asset=asset.strip(),
    description=description.strip(),
    evidence=evidence.strip(),
    remediation=remediation.strip(),
   )
   self.db.add(finding)
   self.db.commit()

   log_activity(
    self.db,self.project_id,
    "Potential finding created",
    f"Finding #{finding.id}: {finding.title}"
   )
   self.refresh_all()
   QMessageBox.information(
    self,"Finding created",
    f"Finding #{finding.id} saved as POTENTIAL with LOW confidence. "
    "It has not been independently verified."
   )
  except Exception as e:
   self.db.rollback()
   QMessageBox.warning(self,"Create finding",str(e))

 def edit_finding_ui(self):
  try:
   self.require_project()
   item=self.finding_list.currentItem()
   if not item or not item.data(Qt.UserRole):
    raise ValueError("Select a finding first.")

   finding=self.db.get(Finding,item.data(Qt.UserRole))
   if not finding or finding.project_id!=self.project_id:
    raise ValueError("Finding not found in the selected project.")

   title,ok=QInputDialog.getText(
    self,"Edit finding","Title:",text=finding.title
   )
   if not ok or not title.strip():
    return

   categories=[
    "Access Control","Authentication","Injection","XSS",
    "SSRF","Security Misconfiguration","Information Disclosure",
    "Cryptography","Business Logic","API Security","Other"
   ]
   category,ok=QInputDialog.getItem(
    self,"Finding category","Category:",categories,
    categories.index(finding.category) if finding.category in categories else 0,
    False
   )
   if not ok:
    return

   severities=["info","low","medium","high","critical"]
   severity,ok=QInputDialog.getItem(
    self,"Finding severity","Severity:",severities,
    severities.index(finding.severity) if finding.severity in severities else 1,
    False
   )
   if not ok:
    return

   confidences=["low","medium","high"]
   confidence,ok=QInputDialog.getItem(
    self,"Finding confidence","Evidence confidence:",confidences,
    confidences.index(finding.confidence) if finding.confidence in confidences else 0,
    False
   )
   if not ok:
    return

   statuses=[
    "potential","needs_review","confirmed","rejected","resolved"
   ]
   status,ok=QInputDialog.getItem(
    self,"Finding review status","Review status:",statuses,
    statuses.index(finding.status) if finding.status in statuses else 0,
    False
   )
   if not ok:
    return

   asset,ok=QInputDialog.getText(
    self,"Affected asset","Hostname or endpoint:",text=finding.asset or ""
   )
   if not ok:
    return

   description,ok=QInputDialog.getMultiLineText(
    self,"Technical description","Description and impact:",
    finding.description or ""
   )
   if not ok:
    return

   evidence,ok=QInputDialog.getMultiLineText(
    self,"Evidence and reproduction","Observed evidence and safe reproduction steps:",
    finding.evidence or ""
   )
   if not ok:
    return

   remediation,ok=QInputDialog.getMultiLineText(
    self,"Remediation","Recommended fix:",finding.remediation or ""
   )
   if not ok:
    return

   review_notes,ok=QInputDialog.getMultiLineText(
    self,
    "Review notes",
    "Explain the review decision, validation performed, or reason for the change:",
    ""
   )
   if not ok:
    return

   previous_status=finding.status
   previous_severity=finding.severity
   previous_confidence=finding.confidence

   finding.title=title.strip()
   finding.category=category
   finding.severity=severity
   finding.confidence=confidence
   finding.status=status
   finding.asset=asset.strip()
   finding.description=description.strip()
   finding.evidence=evidence.strip()
   finding.remediation=remediation.strip()

   review_record=FindingReview(
    project_id=self.project_id,
    finding_id=finding.id,
    previous_status=previous_status,
    new_status=finding.status,
    previous_severity=previous_severity,
    new_severity=finding.severity,
    previous_confidence=previous_confidence,
    new_confidence=finding.confidence,
    reviewer="Local user",
    notes=review_notes.strip(),
   )
   self.db.add(review_record)

   # Finding update and review history are saved atomically.
   self.db.commit()

   log_activity(
    self.db,self.project_id,
    "Finding reviewed",
    f"Finding #{finding.id}: {previous_status} -> {status}; "
    f"severity={severity}; confidence={confidence}"
   )
   self.refresh_all()
   QMessageBox.information(
    self,"Finding saved",
    f"Finding #{finding.id} updated. Review status: {status.upper()}."
   )
  except Exception as e:
   self.db.rollback()
   QMessageBox.warning(self,"Edit finding",str(e))

 def view_finding_history_ui(self):
  try:
   self.require_project()

   item=self.finding_list.currentItem()
   if not item or not item.data(Qt.UserRole):
    raise ValueError("Select a finding first.")

   finding=self.db.get(Finding,item.data(Qt.UserRole))
   if not finding or finding.project_id!=self.project_id:
    raise ValueError("Finding not found in the selected project.")

   records=self.db.scalars(
    select(FindingReview)
    .where(
     FindingReview.project_id==self.project_id,
     FindingReview.finding_id==finding.id
    )
    .order_by(FindingReview.created_at.desc(),FindingReview.id.desc())
   ).all()

   if not records:
    QMessageBox.information(
     self,
     "Finding review history",
     f"Finding #{finding.id}: {finding.title}\\n\\n"
     "No structured review history has been recorded yet. "
     "Edit/review this finding to create the first record."
    )
    return

   lines=[
    f"Finding #{finding.id}: {finding.title}",
    f"Current status: {finding.status}",
    ""
   ]

   for record in records:
    timestamp=(
     record.created_at.isoformat()
     if record.created_at else "Unknown time"
    )
    lines.extend([
     f"REVIEW #{record.id} — {timestamp}",
     f"Reviewer: {record.reviewer}",
     f"Status: {record.previous_status} -> {record.new_status}",
     f"Severity: {record.previous_severity} -> {record.new_severity}",
     f"Confidence: {record.previous_confidence} -> {record.new_confidence}",
     f"Notes: {record.notes or 'No additional notes recorded.'}",
     "-" * 55,
     ""
    ])

   QMessageBox.information(
    self,
    "Finding review history",
    "\\n".join(lines)
   )

  except Exception as e:
   QMessageBox.warning(self,"Review history",str(e))



 def view_validation_details_ui(self):
  """Show the latest database-only validation record for a finding."""
  try:
   self.require_project()

   selected=self.finding_list.currentItem()
   if not selected or not selected.data(Qt.UserRole):
    raise ValueError("Select a finding first.")

   finding=self.db.get(Finding,selected.data(Qt.UserRole))
   if not finding or finding.project_id!=self.project_id:
    raise ValueError("Finding not found in the selected project.")

   checks=self.db.scalars(
    select(ScanCheck)
    .where(
     ScanCheck.project_id==self.project_id,
     ScanCheck.check_name=="Automated finding validation",
     ScanCheck.asset==finding.asset,
    )
    .order_by(ScanCheck.id.desc())
   ).all()

   record=None
   for check in checks:
    try:
     candidate=json.loads(check.details or "{}")
    except (TypeError,ValueError):
     continue
    if (
     candidate.get("record_type")=="bughunter_validation"
     and candidate.get("finding_id")==finding.id
    ):
     record=candidate
     break

   lines=[
    f"FINDING #{finding.id}: {finding.title}",
    f"Status: {finding.status}",
    f"Severity: {finding.severity} | Confidence: {finding.confidence}",
    f"Asset: {finding.asset or 'Not recorded'}",
    "",
    "AUTOMATED VALIDATION",
   ]

   if record is None:
    lines.extend([
     "Classification: NOT YET VALIDATED",
     "No validation record exists for this finding.",
     "Use VALIDATE FINDINGS to correlate existing passive evidence.",
    ])
   else:
    lines.extend([
     f"Classification: {record.get('classification','unknown')}",
     f"Family: {record.get('family','unknown')}",
     f"Rationale: {record.get('rationale') or 'Not recorded'}",
     "",
     "MATCHED CHECKS:",
    ])

    matched=record.get("matched_checks",[])
    if isinstance(matched,list) and matched:
     for entry in matched[:50]:
      if isinstance(entry,dict):
       check_id=entry.get("check_id", entry.get("id", "unknown"))
       lines.append(
        f"- Source check #{check_id}: "
        f"{entry.get('check_name','Unknown check')} "
        f"[{entry.get('outcome','unknown')}]"
       )
       lines.append(
        f"  Asset: {entry.get('asset') or 'Not recorded'} | "
        f"Observed: {entry.get('observed_at') or 'Time not recorded'}"
       )
      else:
       lines.append(f"- {str(entry)[:300]}")
    else:
     lines.append("- No matching completed checks recorded.")

    lines.extend(["", "INDICATOR NAMES:"])
    indicators=record.get("indicator_names",[])
    if isinstance(indicators,list) and indicators:
     lines.extend(f"- {str(name)[:200]}" for name in indicators[:100])
    else:
     lines.append("- None recorded.")

   lines.extend([
    "",
    "SAFETY AND REVIEW LIMITS:",
    "- Passive evidence correlation only; not proof of exploitability.",
    "- Network requests made: 0",
    "- Payloads executed: 0",
    "- Automatically confirmed: No",
    "- Manual review required: Yes",
    "",
    "Opening this view does not change the finding's status.",
   ])

   dialog=QDialog(self)
   dialog.setWindowTitle(f"Validation details — Finding #{finding.id}")
   dialog.resize(760,620)
   layout=QVBoxLayout(dialog)

   viewer=QTextEdit(dialog)
   viewer.setReadOnly(True)
   viewer.setPlainText("\\n".join(lines))
   layout.addWidget(viewer)

   close_button=QPushButton("CLOSE")
   close_button.clicked.connect(dialog.accept)
   layout.addWidget(close_button)
   dialog.exec()

  except Exception as e:
   QMessageBox.warning(self,"Validation details",str(e))


 def validate_findings_ui(self):
  try:
   self.require_project()

   project = self.db.get(Project, self.project_id)
   if not project or not project.scope_approved:
    raise ValueError(
     "Approve the project's scope before validating its findings."
    )

   result = validate_project_findings(self.db, self.project_id)

   self.refresh_findings()
   self.refresh_checks()
   self.refresh_overview()

   QMessageBox.information(
    self,
    "Finding validation complete",
    "Existing passive evidence correlation completed.\n\n"
    f"Potential findings examined: {result.get('findings_examined', 0)}\n"
    f"Supported by observation: {result.get('supported_by_observation', 0)}\n"
    f"Needs manual review: {result.get('needs_manual_review', 0)}\n"
    f"Insufficient evidence: {result.get('insufficient_evidence', 0)}\n\n"
    "Network requests made: 0\n"
    "Payloads executed: 0\n\n"
    "No finding was automatically confirmed. Review each result and "
    "record reproducible evidence before changing a finding's status."
   )

  except Exception as e:
   self.db.rollback()
   QMessageBox.warning(self, "Finding validation", str(e))

 def refresh_findings(self):
  if not hasattr(self, "finding_list"):
   return

  self.finding_list.clear()

  if not self.project_id:
   self.finding_list.addItem("Select a project to view findings.")
   return

  project = self.db.get(Project, self.project_id)
  if not project:
   return

  findings = self.db.scalars(
   select(Finding)
   .where(Finding.project_id == self.project_id)
   .order_by(Finding.id.desc())
  ).all()

  # Load the latest automated validation record for each finding.
  validation_checks = self.db.scalars(
   select(ScanCheck)
   .where(
    ScanCheck.project_id == self.project_id,
    ScanCheck.check_name == "Automated finding validation",
   )
   .order_by(ScanCheck.id.desc())
  ).all()

  validations = {}

  for check in validation_checks:
   try:
    record = json.loads(check.details or "{}")
   except (TypeError, ValueError):
    continue

   if (
    record.get("record_type") != "bughunter_validation"
    or not isinstance(record.get("finding_id"), int)
   ):
    continue

   finding_id = record["finding_id"]
   if finding_id not in validations:
    validations[finding_id] = record

  labels = {
   "supported_by_observation":
    "OBSERVATION SUPPORT — NOT CONFIRMED",
   "needs_manual_review":
    "MANUAL REVIEW NEEDED",
   "insufficient_evidence":
    "INSUFFICIENT EVIDENCE",
  }

  for finding in findings:
   record = validations.get(finding.id)

   if record:
    classification = record.get("classification", "")
    validation_label = labels.get(
     classification, "VALIDATION STATUS UNKNOWN"
    )
    indicators = record.get("indicator_names", [])
    matched_checks = record.get("matched_checks", [])
    rationale = record.get("rationale", "No explanation recorded.")

    if not isinstance(indicators, list):
     indicators = []
    if not isinstance(matched_checks, list):
     matched_checks = []

    indicator_text = ", ".join(
     str(name)[:120] for name in indicators[:20]
    ) or "No matching indicator names recorded."

    check_text = "\n".join(
     f"- {entry.get('check_name', 'Unknown check')} "
     f"[{entry.get('outcome', 'unknown')}]"
     for entry in matched_checks[:15]
     if isinstance(entry, dict)
    ) or "No related completed checks recorded."

    tooltip = (
     f"AUTOMATED VALIDATION: {validation_label}\n"
     f"Finding family: {record.get('family', 'Unknown')}\n\n"
     f"Rationale:\n{rationale}\n\n"
     f"Indicator names:\n{indicator_text}\n\n"
     f"Related checks:\n{check_text}\n\n"
     "This is passive evidence correlation, not proof of exploitability. "
     "Manual review and reproducible evidence are required. "
     "BugHunter AI has not automatically confirmed this finding."
    )
   else:
    validation_label = "NOT YET VALIDATED"
    tooltip = (
     "No automated validation record exists for this finding yet. "
     "A future completed assessment may provide related passive evidence. "
     "Manual review is still required."
    )

   item = QListWidgetItem(
    f"#{finding.id} [{finding.severity.upper()} / "
    f"{finding.status.upper()} / {finding.confidence.upper()}] "
    f"{finding.title} — {finding.asset or 'Asset not recorded'}\n"
    f"   AUTOMATED VALIDATION: {validation_label}"
   )
   item.setData(Qt.UserRole, finding.id)
   item.setToolTip(tooltip)
   self.finding_list.addItem(item)

  if not findings:
   self.finding_list.addItem(
    "No findings recorded. Use CREATE FINDING or the OWASP Test Plan."
   )

 def analyze(self):
  try:
   self.require_project(); p=self.db.get(Project,self.project_id); r=analyze_programme(p.programme_url,self.policy.toPlainText())
   p.policy_text=r["policy_text"]; p.description=r["title"]; self.db.commit(); log_activity(self.db,p.id,"Programme analyzed",f"Source: {r['source']}; candidates: {len(r['candidate_domains'])}")
   QMessageBox.information(self,"Review required",f"Title: {r['title']}\nCandidate domains: {', '.join(r['candidate_domains']) or 'none'}\n\n{r['warning']}\nScope is not approved automatically.")
  except Exception as e: QMessageBox.warning(self,"Analyzer",str(e))
 def add_host(self):
  try:
   self.require_project()
   project = self.db.get(Project, self.project_id)
   was_approved = bool(project and project.scope_approved)

   host, ok = QInputDialog.getText(
    self,
    "Add asset",
    "Exact authorized hostname or IP address only (no scheme/path):"
   )
   if not ok or not host.strip():
    return

   add_scope_asset(self.db, self.project_id, host)
   self.refresh_all()

   if was_approved:
    QMessageBox.warning(
     self,
     "Scope approval revoked",
     "The asset was added, but the previous project approval was revoked. "
     "All hosts are now unapproved. Review the complete updated scope and "
     "approve it again before starting another assessment."
    )

  except Exception as e:
   self.db.rollback()
   QMessageBox.warning(self, "Scope", str(e))
 def approve(self):
  try:
   self.require_project()
   project = self.db.get(Project, self.project_id)

   if not project:
    raise ValueError("Selected project not found.")

   policy_text = self.policy.toPlainText().strip()
   if not policy_text:
    raise ValueError(
     "Paste or retrieve the official programme policy before approval."
    )

   assets = self.db.scalars(
    select(ScopeAsset).where(
     ScopeAsset.project_id == project.id,
     ScopeAsset.included.is_(True)
    ).order_by(ScopeAsset.host.asc())
   ).all()

   if not assets:
    raise ValueError("Add at least one included asset.")

   host_list = "\\n".join(
    f"  • {asset.host}" for asset in assets
   )

   confirmation = QMessageBox.question(
    self,
    "Confirm authorized scope",
    "You are about to approve this exact scope:\\n\\n"
    f"Programme: {project.programme_url or 'NOT RECORDED'}\\n\\n"
    f"Included hosts ({len(assets)}):\\n{host_list}\\n\\n"
    "Confirm that you have reviewed the official policy, have written "
    "authorization to test every listed host, and have checked exclusions, "
    "testing restrictions and permitted methods.\\n\\n"
    "Only the listed included hosts will be approved. "
    "Discovered candidates are not included automatically.",
    QMessageBox.Yes | QMessageBox.No,
    QMessageBox.No,
   )

   if confirmation != QMessageBox.Yes:
    return

   project.policy_text = policy_text
   approve_scope(self.db, project)
   self.refresh_all()

   QMessageBox.information(
    self,
    "Scope approved",
    f"{len(assets)} included host(s) approved. "
    "Any later scope change will revoke this approval and require a new review."
   )

  except Exception as e:
   self.db.rollback()
   QMessageBox.warning(self, "Scope", str(e))
 def start_website_analysis(self):
  try:
   self.require_project()
   if self.api_client is not None:
    raise ValueError("Persistent hunts currently run only in the local SQLite workspace. Central-server worker execution is not yet available.")
   from app.services.workflows import validate_target
   url=self.website_url.text().strip()
   if not url:
    QMessageBox.warning(self,"Target required","Enter an HTTPS URL belonging to an approved asset.")
    return
   parsed=validate_target(self.db,self.project_id,url)
   if parsed.scheme.lower()!="https" or parsed.port not in (None,443):
    raise ValueError("Automated hunts require an approved HTTPS target on standard port 443.")
   active=[job for job in list_jobs(self.db,self.project_id) if job.job_type=="Automated hunt" and job.status in {"queued","running"}]
   if active:
    QMessageBox.information(self,"Hunt already active",f"Automated hunt #{active[0].id} is already {active[0].status}.")
    self.refresh_evidence_jobs()
    return
   answer=QMessageBox.question(self,"Confirm authorized hunt","Queue a persistent hunt using passive DNS/certificate discovery and bounded, rate-limited HTTPS GET discovery on the exact approved host. New discoveries remain unapproved. No exploit payloads, state-changing requests, or automatic vulnerability confirmation will run. Continue?",QMessageBox.Yes|QMessageBox.No)
   if answer!=QMessageBox.Yes:
    return
   job=create_hunt_job(self.db,self.project_id,url,max_pages=25)
   try:
    service=subprocess.run(["systemctl","--user","start","bughunter-hunt-worker.service"],capture_output=True,text=True,check=False)
   except OSError:
    service=None
   self.website_progress.setValue(0)
   if service is not None and service.returncode==0:
    self.website_status.setText(f"Hunt #{job.id} queued. Persistent worker is starting.")
    QMessageBox.information(self,"Hunt queued",f"Automated hunt #{job.id} has been queued. It will continue independently of this window while the worker service is running.")
   else:
    root=Path(__file__).resolve().parents[2]
    installer=root/"scripts"/"install_hunt_worker.sh"
    self.website_status.setText(f"Hunt #{job.id} queued; persistent worker setup is required.")
    QMessageBox.information(self,"Hunt queued — worker setup required",f"Hunt #{job.id} is safely stored in the job queue. To let it run independently, open a terminal in the project folder and run:\n\nbash scripts/install_hunt_worker.sh\n\nExpected installer: {installer}")
   self.refresh_evidence_jobs()
  except Exception as e:
   self.db.rollback()
   QMessageBox.warning(self,"Automated hunt",str(e))

 def stop_website_analysis(self):
  try:
   self.require_project()
   active=[job for job in list_jobs(self.db,self.project_id) if job.job_type=="Automated hunt" and job.status in {"queued","running"}]
   if not active:
    self.refresh_evidence_jobs()
    return
   job=active[0]
   answer=QMessageBox.question(self,"Stop automated hunt",f"Request a safe stop for hunt #{job.id}? The current bounded DNS/HTTP operation may finish before stopping.",QMessageBox.Yes|QMessageBox.No)
   if answer!=QMessageBox.Yes:
    return
   transition_job(self.db,job.id,"stopped",progress=job.progress,checkpoint="Stop requested from the desktop interface. The worker will stop at its next cooperative checkpoint.")
   self.website_status.setText(f"Stop requested for hunt #{job.id}.")
   self.refresh_evidence_jobs()
  except Exception as e:
   self.db.rollback()
   QMessageBox.warning(self,"Stop hunt",str(e))
 def update_website_progress(self,percent,message):
  self.website_progress.setValue(percent)
  self.website_status.setText(message)

 def website_analysis_result(self,stats):
  self.refresh_all()

  intelligence = stats.get("project_intelligence") or {}
  assessment = intelligence.get("assessment") or {}
  assessment_summary = assessment.get("summary") or {}
  coverage = intelligence.get("coverage") or {}
  coverage_summary = coverage.get("summary") or {}
  findings = intelligence.get("finding_summary") or {}
  duplicates = intelligence.get("duplicate_review") or {}
  resources = intelligence.get("resource_summary") or {}

  intelligence_summary = (
   "\\n\\nATTACK-SURFACE ASSESSMENT\\n"
   f"Endpoints in assessment: {assessment_summary.get('endpoints', 0)}\\n"
   f"Assessment recommendations: {assessment_summary.get('recommendations', 0)}\\n"
   f"Recorded completed assessments: {assessment_summary.get('completed', 0)}"
   f"/{assessment_summary.get('applicable', 0)}\\n"
   f"Recorded assessment progress: {assessment_summary.get('completion_percent', 0)}%\\n"
   f"Endpoints with recommendations: {resources.get('endpoints_with_recommendations', 0)}\\n"
   f"Endpoints without recommendations: {resources.get('endpoints_without_recommendations', 0)}\\n"
   f"API resource groups: {resources.get('resource_groups', 0)}\\n"
   f"Approved assets: {coverage_summary.get('approved_assets', 0)}\\n"
   f"Assets assessed: {coverage_summary.get('assessed_assets', 0)}\\n"
   f"Potential findings: {findings.get('potential', 0)}\\n"
   f"Confirmed/verified findings: {findings.get('confirmed_or_verified', 0)}\\n"
   f"Exact duplicate groups for review: {duplicates.get('exact_group_count', 0)}\\n"
   f"Possible duplicate pairs for review: {duplicates.get('possible_pair_count', 0)}\\n"
   "Assessment recommendations are review tasks, not proof of vulnerabilities.\\n"
   "No additional network requests or test payloads were executed by this summary."
  )

  if intelligence.get("error"):
   intelligence_summary = (
    "\\n\\nProject intelligence summary unavailable: "
    + intelligence.get("message", "Unknown error")
   )

  request_summary = (
   f"Page requests attempted: {stats.get('requests_attempted', 0)}\\n"
   f"Robots.txt requests: {stats.get('robots_requests', 0)}\\n"
   f"Pages checked: {stats['pages_checked']}\\n"
   f"Requests failed: {stats['requests_failed']}\\n"
   f"Endpoints discovered: {stats['endpoints_discovered']}\\n"
   f"JavaScript assets reviewed: {stats.get('javascript_assets_checked', 0)}\\n"
   f"Client-side routes discovered: {stats.get('client_routes_discovered', 0)}\\n"
   f"Sensitive markers detected: {stats.get('sensitive_markers_detected', 0)}\\n"
   f"Potential client-side security patterns: {stats.get('client_security_patterns_detected', 0)}\\n"
   f"Forms reviewed: {stats.get('forms_detected', 0)}\\n"
   f"Potential CSRF issues: {stats.get('csrf_candidate_forms_detected', 0)}\\n"
   f"SQL error indicators: {stats.get('sql_error_indicators_detected', 0)}\\n"
   f"API sensitive-field indicators: {stats.get('api_sensitive_fields_detected', 0)}\\n"
   f"API verbose-error indicators: {stats.get('api_verbose_errors_detected', 0)}\\n"
   f"Exposure indicators: {stats.get('exposure_indicators', 0)}\\n"
   f"Potential findings created: {stats['findings_created']}\\n"
   "Note: Indicators are leads for manual review, not confirmed vulnerabilities."
  ) + intelligence_summary

  request_summary += (
   "\\n\\nOPENAPI DOCUMENTATION REVIEW\\n"
   f"Documents reviewed: {stats.get('openapi_documents_reviewed', 0)}\\n"
   f"Operations reviewed: {stats.get('openapi_operations_reviewed', 0)}\\n"
   f"Operations registered: {stats.get('openapi_operations_registered', 0)}\\n"
   f"Operations skipped: {stats.get('openapi_operations_skipped', 0)}\\n"
   f"Identity-related parameters: {stats.get('openapi_identity_parameters_detected', 0)}\\n"
   f"Sensitive parameter names: {stats.get('openapi_sensitive_parameters_detected', 0)}\\n"
   f"Operations without documented security: {stats.get('openapi_operations_without_security', 0)}\\n"
   f"Request-body fields discovered: {stats.get('openapi_body_fields_discovered', 0)}\\n"
   "Documented operations were not invoked. Missing security declarations "
   "are review indicators, not confirmed vulnerabilities."
  )


  if stats.get("stopped"):
   QMessageBox.information(
    self,
    "Analysis stopped",
    "The website analysis stopped safely.\\n\\n"
    + request_summary
   )
  else:
   limit_note = (
    "\\n\\nThe page-request limit was reached. "
    "Some discovered pages may remain untested."
    if stats.get("request_limit_reached")
    else ""
   )

   QMessageBox.information(
    self,
    "Analysis completed",
    "Website analysis completed. This is not a comprehensive security audit.\\n\\n"
    + request_summary
    + limit_note
   )

 def website_analysis_error(self,message):
  self.refresh_all()
  QMessageBox.warning(
   self,
   "Website analysis failed",
   message
  )

 def website_worker_finished(self):
  self.start_website_button.setEnabled(True)
  self.stop_website_button.setEnabled(False)

  if self.analysis_worker is not None:
   self.analysis_worker=None

  self.refresh_all()

 def closeEvent(self,event):
  passive_worker=self.passive_recon_worker
  if passive_worker is not None and passive_worker.isRunning():
   answer=QMessageBox.question(
    self,
    "Passive reconnaissance still running",
    "Passive reconnaissance is running. Request a safe stop and wait?",
    QMessageBox.Yes|QMessageBox.No
   )
   if answer!=QMessageBox.Yes:
    event.ignore()
    return
   passive_worker.request_stop()
   if not passive_worker.wait(20000):
    QMessageBox.warning(
     self,"Passive reconnaissance still running",
     "The current DNS or CT operation has not finished. Wait before closing."
    )
    event.ignore()
    return

  worker=self.analysis_worker

  if worker is not None and worker.isRunning():
   answer=QMessageBox.question(
    self,
    "Analysis still running",
    "A website analysis is running. Request a stop and wait for it to finish?",
    QMessageBox.Yes|QMessageBox.No
   )

   if answer!=QMessageBox.Yes:
    event.ignore()
    return

   worker.request_stop()

   if not worker.wait(15000):
    QMessageBox.warning(
     self,
     "Analysis still running",
     "The current network request has not finished yet. "
     "Wait for it to finish before closing the application."
    )
    event.ignore()
    return

  event.accept()

 def hunt(self):
  try:
   self.require_project()
   if QMessageBox.question(self,"Authorization","Run non-destructive HTTPS GET and security-header checks on approved assets?")!=QMessageBox.Yes: return
   run_safe_assessment(self.db,self.project_id); self.refresh_all()
   QMessageBox.information(self,"Complete","Checks completed. Review results; this is not a comprehensive security audit.")
  except Exception as e: QMessageBox.warning(self,"Assessment",str(e))
 def export(self):
  try:
   from app.core.config import DATA_DIR
   self.require_project()
   from pathlib import Path

   report_dir=DATA_DIR/"reports"/f"account_{self.user_id}"/f"project_{self.project_id}"
   report_dir.mkdir(parents=True,exist_ok=True)

   path,_=QFileDialog.getSaveFileName(
    self,
    "Export professional project report",
    str(report_dir/"bughunter-report.json"),
    "JSON (*.json);;Markdown (*.md);;HTML (*.html);;PDF (*.pdf);;Word Document (*.docx)"
   )
   if not path:
    return

   fmt=path.rsplit(".",1)[-1].lower()
   fmt={"md":"markdown"}.get(fmt,fmt)
   saved=export_report(self.db,self.project_id,path,fmt)

   QMessageBox.information(
    self,"Report exported",
    f"Report saved successfully:\\n{saved}\\n\\n"
    "The report includes project scope, findings, checks, attack surface, "
    "test-plan records, evidence hashes, assessment jobs and activity history."
   )
  except Exception as e:
   self.db.rollback()
   QMessageBox.warning(self,"Report export",str(e))
def run():
 if ENABLE_LOCAL_MODE:
  init_db()
 app=QApplication(sys.argv)
 w=Window()
 w.show()
 code=app.exec()
 if w.api_client is not None:
  w.api_client.close()
 if w.db is not None:
  w.db.close()
 return code
