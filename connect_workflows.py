from pathlib import Path
import shutil

path = Path("app/ui/main_window.py")
source = path.read_text()

if "ATTACK_SURFACE_WORKFLOW_V1" in source:
    raise SystemExit("Workflow UI already installed. No changes made.")

backup = path.with_name("main_window.py.workflow-backup")
shutil.copy2(path, backup)

# Add imports.
source = source.replace(
    "from app.models.entities import User,Project,Finding,ScanCheck,ScopeAsset,Activity",
    "from app.models.entities import User,Project,Finding,ScanCheck,ScopeAsset,Activity,Endpoint,TestCase",
    1
)

source = source.replace(
    "QListWidget,QInputDialog",
    "QListWidget,QListWidgetItem,QInputDialog",
    1
)

source = source.replace(
    "from app.services.auth import authenticate",
    "from app.services.auth import authenticate\nfrom app.services.workflows import add_endpoint,initialize_test_plan,update_test_case",
    1
)

# Insert the new tabs before the dashboard is displayed.
anchor = "  self.setCentralWidget(tabs)"
assert anchor in source, "Dashboard insertion point not found."

tabs = '''
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
  attack_layout.addLayout(endpoint_buttons)

  self.endpoint_list=QListWidget()
  attack_layout.addWidget(self.endpoint_list)
  tabs.addTab(attack,"Attack Surface")

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
  plan_layout.addWidget(self.test_case_list)
  tabs.addTab(plan,"OWASP Test Plan")

'''

source = source.replace(anchor, tabs + anchor, 1)

# Add methods before require_project.
anchor = " def require_project(self):"
assert anchor in source, "Could not find require_project."

methods = '''
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

 def refresh_workflow_views(self):
  if not hasattr(self,"endpoint_list"):
   return

  self.endpoint_list.clear()
  self.test_case_list.clear()

  if not self.project_id:
   self.endpoint_list.addItem("Select a project first.")
   self.test_case_list.addItem("Select a project first.")
   return

  endpoints=self.db.scalars(
   select(Endpoint)
   .where(Endpoint.project_id==self.project_id)
   .order_by(Endpoint.id.desc())
  ).all()

  if endpoints:
   for endpoint in endpoints:
    item=QListWidgetItem(
     f"#{endpoint.id} | {endpoint.method} | "
     f"{endpoint.endpoint_type} | {endpoint.url}"
    )
    item.setData(Qt.UserRole,endpoint.id)
    self.endpoint_list.addItem(item)
  else:
   self.endpoint_list.addItem("No endpoints registered yet.")

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

   notes,ok=QInputDialog.getMultiLineText(
    self,"Assessment observations",
    "Record what you tested, your observations, limitations and evidence:",
    test.notes
   )
   if not ok:
    return

   update_test_case(
    self.db,self.project_id,test.id,status,target.strip(),notes
   )
   self.refresh_workflow_views()

   QMessageBox.information(
    self,"Test updated","Assessment record saved successfully."
   )
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

'''

source = source.replace(anchor, methods + anchor, 1)

# Refresh new tabs when a project is selected.
select_anchor = "  self.refresh_all()\n  self.statusBar().showMessage(f\"Selected project #{self.project_id}\")"
assert select_anchor in source, "Project selection refresh point not found."

source = source.replace(
 select_anchor,
 "  self.refresh_all()\n  self.refresh_workflow_views()\n  self.statusBar().showMessage(f\"Selected project #{self.project_id}\")",
 1
)

# Also refresh the new lists from the main refresh action.
refresh_anchor = "  self.refresh_checks()\n"
assert refresh_anchor in source, "Could not find dashboard refresh method."

source = source.replace(
 refresh_anchor,
 refresh_anchor + "  self.refresh_workflow_views()\n",
 1
)

path.write_text(source)
print("SUCCESS: Attack Surface and OWASP Test Plan tabs installed.")
print(f"Backup saved to: {backup}")
