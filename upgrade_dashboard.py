from pathlib import Path
import shutil

path = Path("app/ui/main_window.py")
source = path.read_text()

backup = path.with_name("main_window.py.dashboard-backup")
shutil.copy2(path, backup)

# Add the widgets needed by the upgraded interface.
source = source.replace(
    "QToolButton",
    "QToolButton,QGroupBox,QGridLayout,QFrame,QHeaderView,QTableWidget,QTableWidgetItem",
    1
)

source = source.replace(
    "from app.models.entities import User,Project,Finding,ScanCheck",
    "from app.models.entities import User,Project,Finding,ScanCheck,ScopeAsset,Activity",
    1
)

start = source.index(" def dashboard(self):")
end = source.index(" def require_project(self):", start)

new_dashboard = '''
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

  lower.addWidget(projects_box)
  lower.addWidget(activity_box)
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
  refresh_button=QPushButton("REFRESH PROJECTS")
  refresh_button.clicked.connect(self.refresh_projects)
  project_row.addWidget(refresh_button)
  pl.addLayout(project_row)

  self.project_list=QListWidget()
  self.project_list.itemClicked.connect(self.select_project)
  pl.addWidget(QLabel("Select a project to work on:"))
  pl.addWidget(self.project_list)
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
  self.finding_list=QListWidget()
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
  tabs.addTab(activity,"Activity & Evidence")

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
   ("Evidence vault","Finding evidence is currently stored in the database. File attachments are not yet implemented.")
  ]:
   group=QGroupBox(title)
   group_layout=QVBoxLayout(group)
   description_label=QLabel(description)
   description_label.setWordWrap(True)
   group_layout.addWidget(description_label)
   tool_layout.addWidget(group)
  tool_layout.addStretch()
  tabs.addTab(tools,"Tools & Settings")

  self.setCentralWidget(tabs)
  self.statusBar().showMessage("BugHunter AI ready — select a project before working with scope or findings.")
  self.refresh_projects()
  self.refresh_all()

 def select_recent_project(self,item):
  self.select_project(item)

 def refresh_overview(self):
  projects=self.db.scalars(select(Project).order_by(Project.id.desc())).all()
  assets=self.db.scalar(select(func.count(ScopeAsset.id))) or 0
  findings=self.db.scalar(select(func.count(Finding.id))) or 0
  checks=self.db.scalar(select(func.count(ScanCheck.id))) or 0
  approved=self.db.scalar(select(func.count(ScopeAsset.id)).where(
   ScopeAsset.approved.is_(True),ScopeAsset.included.is_(True)
  )) or 0

  self.metric_projects.setText(str(len(projects)))
  self.metric_assets.setText(str(assets))
  self.metric_findings.setText(str(findings))
  self.metric_checks.setText(str(checks))
  self.metric_approved.setText(str(approved))

  self.recent_projects.clear()
  for project in projects[:10]:
   self.recent_projects.addItem(f"{project.id} — {project.name} [{project.status}]")

  self.recent_activity.clear()
  events=self.db.scalars(
   select(Activity).order_by(Activity.created_at.desc()).limit(12)
  ).all()
  for event in events:
   self.recent_activity.addItem(
    f"{event.event} | Project #{event.project_id} | {event.details[:100]}"
   )

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

 def refresh_all(self):
  self.refresh_overview()
  self.refresh_activity()
  self.refresh_checks()
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
'''

source = source[:start] + new_dashboard + source[end:]

# Update project selection to refresh all project-related screens.
source = source.replace(
''' def select_project(self,item):
  self.project_id=int(item.text().split(" — ")[0]); self.refresh_scope(); self.refresh_findings()
''',
''' def select_project(self,item):
  self.project_id=int(item.text().split(" — ")[0])
  self.refresh_all()
  self.statusBar().showMessage(f"Selected project #{self.project_id}")
''',
1
)

# Make project creation update the overview as well.
source = source.replace(
'''  try: p=create_project(self.db,self.pname.text(),self.purl.text()); self.refresh_projects(); QMessageBox.information(self,"Project",f"Created project #{p.id}.")
''',
'''  try: p=create_project(self.db,self.pname.text(),self.purl.text()); self.refresh_projects(); self.refresh_all(); QMessageBox.information(self,"Project",f"Created project #{p.id}.")
''',
1
)

# Refresh all views after assessment and scope approval.
source = source.replace(
'''   self.require_project(); approve_scope(self.db,self.db.get(Project,self.project_id)); self.refresh_scope()
''',
'''   self.require_project(); approve_scope(self.db,self.db.get(Project,self.project_id)); self.refresh_all()
''',
1
)

source = source.replace(
'''   run_safe_assessment(self.db,self.project_id); self.refresh_findings()
''',
'''   run_safe_assessment(self.db,self.project_id); self.refresh_all()
''',
1
)

path.write_text(source)
print("Dashboard upgrade written successfully.")
print(f"Backup: {backup}")
