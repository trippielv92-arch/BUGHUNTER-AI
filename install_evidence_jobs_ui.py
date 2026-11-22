from pathlib import Path
import shutil

path = Path("app/ui/main_window.py")
source = path.read_text()

if "EVIDENCE_JOB_MANAGER_V1" in source:
    raise SystemExit("Already installed. No changes made.")

backup = Path("backups/main_window.py.before-evidence-jobs-ui")
backup.parent.mkdir(parents=True, exist_ok=True)
shutil.copy2(path, backup)

def replace_once(old, new, label):
    global source
    if old not in source:
        raise RuntimeError(f"Missing insertion point: {label}")
    source = source.replace(old, new, 1)

# Imports
replace_once(
    "from PySide6.QtCore import Qt",
    "from PySide6.QtCore import Qt, QUrl\nfrom PySide6.QtGui import QDesktopServices",
    "Qt imports"
)

replace_once(
    "from app.models.entities import User,Project,Finding,ScanCheck,ScopeAsset,Activity,Endpoint,TestCase",
    "from app.models.entities import User,Project,Finding,ScanCheck,ScopeAsset,Activity,Endpoint,TestCase,Evidence,AssessmentJob",
    "model imports"
)

replace_once(
    "from app.services.workflows import add_endpoint,initialize_test_plan,update_test_case",
    "from app.services.workflows import add_endpoint,initialize_test_plan,update_test_case\nfrom app.services.evidence import add_evidence,list_evidence,verify_evidence\nfrom app.services.jobs import create_job,transition_job,list_jobs,recover_interrupted_jobs,ALLOWED_TRANSITIONS",
    "service imports"
)

# Startup recovery
replace_once(
    "self.db=SessionLocal(); self.project_id=None;",
    "self.db=SessionLocal(); recover_interrupted_jobs(self.db); self.project_id=None;",
    "startup recovery"
)

# Rename existing activity tab
replace_once(
    'tabs.addTab(activity,"Activity & Evidence")',
    'tabs.addTab(activity,"Activity")',
    "activity tab"
)

# New tabs
anchor = "  self.setCentralWidget(tabs)"
if anchor not in source:
    raise RuntimeError("Central widget insertion point missing")

tabs = '''
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

'''

source = source.replace(anchor, tabs + anchor, 1)

# Add refresh call using a reliable method boundary.
refresh_start = source.find(" def refresh_all(self):")
if refresh_start < 0:
    raise RuntimeError("refresh_all method not found")

refresh_end = source.find("\n def ", refresh_start + 1)
if refresh_end < 0:
    raise RuntimeError("Could not identify refresh_all method boundary")

refresh_method = source[refresh_start:refresh_end]
if "self.refresh_evidence_jobs()" not in refresh_method:
    refresh_method = refresh_method.rstrip() + "\n  self.refresh_evidence_jobs()\n"
    source = source[:refresh_start] + refresh_method + source[refresh_end:]

# UI methods
anchor = " def require_project(self):"
if anchor not in source:
    raise RuntimeError("require_project method not found")

methods = '''
 def refresh_evidence_jobs(self):
  if not hasattr(self,"evidence_list"):
   return

  self.evidence_list.clear()
  self.job_list.clear()

  if not self.project_id:
   self.evidence_list.addItem("Select a project.")
   self.job_list.addItem("Select a project.")
   return

  for record in list_evidence(self.db,self.project_id):
   item=QListWidgetItem(
    f"#{record.id} | {record.original_name} | "
    f"{record.size_bytes} bytes | SHA256 {record.sha256[:16]}..."
   )
   item.setData(Qt.UserRole,record.id)
   self.evidence_list.addItem(item)

  if not self.evidence_list.count():
   self.evidence_list.addItem("No evidence attached.")

  for job in list_jobs(self.db,self.project_id):
   item=QListWidgetItem(
    f"#{job.id} | {job.job_type} | {job.status.upper()} | "
    f"{job.progress}%"
   )
   item.setData(Qt.UserRole,job.id)
   self.job_list.addItem(item)

  if not self.job_list.count():
   self.job_list.addItem("No jobs recorded.")

 def attach_evidence_ui(self):
  try:
   self.require_project()
   filename,_=QFileDialog.getOpenFileName(self,"Select evidence file")
   if not filename:
    return

   finding_id=None
   selected=self.finding_list.currentItem()
   if selected:
    answer=QMessageBox.question(
     self,"Link evidence","Link to selected finding?",
     QMessageBox.Yes|QMessageBox.No
    )
    if answer==QMessageBox.Yes:
     finding_id=int(selected.text().split(" ",1)[0].lstrip("#"))

   notes,ok=QInputDialog.getMultiLineText(
    self,"Evidence notes","Describe this evidence:"
   )
   if not ok:
    return

   record=add_evidence(
    self.db,self.project_id,filename,notes,finding_id
   )
   self.refresh_evidence_jobs()
   QMessageBox.information(
    self,"Evidence saved",
    f"Evidence #{record.id}\\nSHA-256: {record.sha256}"
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
     self,"Verified",f"SHA-256 matches:\\n{record.sha256}"
    )
   else:
    QMessageBox.warning(
     self,"Verification failed","File missing or hash mismatch."
    )
  except Exception as e:
   QMessageBox.warning(self,"Evidence",str(e))

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

   job=self.db.get(AssessmentJob,item.data(Qt.UserRole))
   if not job or job.project_id!=self.project_id:
    raise ValueError("Job not found.")

   choices=sorted(ALLOWED_TRANSITIONS.get(job.status,set()))
   if not choices:
    raise ValueError("This job has no available status transitions.")

   status,ok=QInputDialog.getItem(
    self,"Update job","New status:",choices,0,False
   )
   if not ok:
    return

   progress,ok=QInputDialog.getInt(
    self,"Progress","Progress percentage:",
    job.progress,0,100
   )
   if not ok:
    return

   checkpoint,ok=QInputDialog.getMultiLineText(
    self,"Checkpoint","Progress and resume notes:",job.checkpoint
   )
   if not ok:
    return

   summary=None
   error=None

   if status=="completed":
    progress=100
    summary,ok=QInputDialog.getMultiLineText(
     self,"Result summary","Describe completed work:"
    )
    if not ok:
     return

   if status=="failed":
    error,ok=QInputDialog.getMultiLineText(
     self,"Failure","Describe the failure:"
    )
    if not ok:
     return

   transition_job(
    self.db,job.id,status,progress=progress,
    checkpoint=checkpoint,
    result_summary=summary,
    error_message=error
   )
   self.refresh_evidence_jobs()
   QMessageBox.information(self,"Job updated","Job record saved.")
  except Exception as e:
   self.db.rollback()
   QMessageBox.warning(self,"Job manager",str(e))

'''

source = source.replace(anchor, methods + anchor, 1)

# Save only after all checks succeed.
compile(source, str(path), "exec")
path.write_text(source)

print("SUCCESS: Evidence Vault and Job Manager installed.")
print("Backup:", backup)
