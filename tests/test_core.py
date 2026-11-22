import pytest
from app.services.auth import create_owner,authenticate
from app.services.projects import create_project,add_scope_asset,approve_scope
from app.services.analyzer import analyze_programme,validate_programme_url
from app.services.research import host_is_approved
from app.services.reports import report_data
def test_auth_hash(db):
 u=create_owner(db,"owner","a-very-long-password")
 assert u.password_hash!="a-very-long-password"
 assert authenticate(db,"owner","a-very-long-password")
 assert not authenticate(db,"owner","wrong")
def test_scope_approval(db):
 p=create_project(db,"Test","https://example.com"); p.policy_text="Authorized test policy for example.com."; a=add_scope_asset(db,p.id,"app.example.com")
 assert not a.approved; approve_scope(db,p); assert p.scope_approved and a.approved
def test_scope_boundary(db):
 p=create_project(db,"Test"); a=add_scope_asset(db,p.id,"example.com"); a.approved=True
 assert host_is_approved("api.example.com",[a]); assert not host_is_approved("notexample.com",[a])
def test_manual_policy(db=None):
 r=analyze_programme("https://example.com","In scope app.example.com; out of scope old.example.net")
 assert "app.example.com" in r["candidate_domains"] and r["source"]=="manual policy text"
def test_https_only():
 with pytest.raises(ValueError): validate_programme_url("http://example.com")
def test_empty_report_is_honest(db):
 p=create_project(db,"No issues","https://example.com"); p.policy_text="Authorized test policy for example.com."; add_scope_asset(db,p.id,"example.com"); approve_scope(db,p)
 assert report_data(db,p.id)["findings"]==[]
 assert "does not establish" in report_data(db,p.id)["assessment_note"]
