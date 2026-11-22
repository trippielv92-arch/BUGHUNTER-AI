"""Evidence-based asset and vulnerability-category coverage."""

from collections import Counter, defaultdict
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import select

from app.services.endpoint_intelligence import analyze_endpoint, safe_endpoint_url

from app.models.entities import (
    Project, ScopeAsset, ScanCheck, Endpoint, Finding,
    AssessmentJob, TestCase,
)

COMPLETED = {"Passed", "Finding identified"}
REVIEW = {"Needs review"}
INCOMPLETE = {"Planned", "In progress", "Blocked"}
NOT_APPLICABLE = {"Not applicable"}


def _host(value):
    try:
        parsed = urlsplit(value if "://" in value else "https://" + value)
        return (parsed.hostname or "").lower().rstrip(".")
    except (TypeError, ValueError):
        return ""


def _is_assessment_check(check):
    name = (check.check_name or "").lower()
    excluded = (
        "dns resolution",
        "certificate transparency",
        "passive reconnaissance",
        "validation review",
        "automated finding validation",
    )
    return not any(item in name for item in excluded)


def _category_progress(tests):
    counts = Counter(test.status for test in tests)
    total = len(tests)
    completed = sum(counts[s] for s in COMPLETED)
    review = sum(counts[s] for s in REVIEW)
    not_applicable = sum(counts[s] for s in NOT_APPLICABLE)
    applicable = total - not_applicable

    if not total:
        status = "not_planned"
    elif applicable == 0:
        status = "not_applicable"
    elif completed == applicable:
        status = (
            "completed_with_findings"
            if counts["Finding identified"] else "completed"
        )
    elif review:
        status = "needs_review"
    elif completed or counts["In progress"]:
        status = "in_progress"
    else:
        status = "not_started"

    return {
        "total": total,
        "applicable": applicable,
        "completed": completed,
        "passed": counts["Passed"],
        "finding_identified": counts["Finding identified"],
        "needs_review": review,
        "planned": counts["Planned"],
        "in_progress": counts["In progress"],
        "blocked": counts["Blocked"],
        "not_applicable": not_applicable,
        "incomplete": sum(counts[s] for s in INCOMPLETE),
        "completion_percent": (
            round(completed / applicable * 100, 2) if applicable else 0
        ),
        "status": status,
    }


def _build_category_rows(tests):
    grouped = defaultdict(list)
    for test in tests:
        grouped[test.category or "Uncategorized"].append(test)

    return [
        {"category": category, **_category_progress(grouped[category])}
        for category in sorted(grouped)
    ]



def _endpoint_key(value):
    """Normalize an endpoint URL without collapsing distinct paths or queries."""
    try:
        parsed = urlsplit((value or "").strip())
        if not parsed.scheme or not parsed.hostname:
            return ""

        scheme = parsed.scheme.lower()
        host = parsed.hostname.lower().rstrip(".")
        port = parsed.port

        if ":" in host and not host.startswith("["):
            host = f"[{host}]"

        if port and not (
            (scheme == "https" and port == 443)
            or (scheme == "http" and port == 80)
        ):
            netloc = f"{host}:{port}"
        else:
            netloc = host

        return urlunsplit((
            scheme,
            netloc,
            parsed.path or "/",
            parsed.query,
            "",
        ))
    except (TypeError, ValueError):
        return ""


def _endpoint_progress(tests):
    progress = _category_progress(tests)
    return {
        "total": progress["total"],
        "applicable": progress["applicable"],
        "completed": progress["completed"],
        "passed": progress["passed"],
        "finding_identified": progress["finding_identified"],
        "needs_review": progress["needs_review"],
        "planned": progress["planned"],
        "in_progress": progress["in_progress"],
        "blocked": progress["blocked"],
        "not_applicable": progress["not_applicable"],
        "completion_percent": progress["completion_percent"],
        "status": progress["status"],
    }


def _resource_assessment_progress(tests):
    """Summarize manual tasks associated with an API resource."""
    progress = _category_progress(tests)

    authorization_tests = [
        test for test in tests
        if (test.category or "").strip().lower() in {
            "authorization", "api security", "authentication"
        }
    ]
    authorization = _category_progress(authorization_tests)

    return {
        "assessment_total": progress["total"],
        "assessment_applicable": progress["applicable"],
        "assessment_completed": progress["completed"],
        "assessment_passed": progress["passed"],
        "assessment_finding_identified": progress["finding_identified"],
        "assessment_needs_review": progress["needs_review"],
        "assessment_planned": progress["planned"],
        "assessment_in_progress": progress["in_progress"],
        "assessment_blocked": progress["blocked"],
        "assessment_not_applicable": progress["not_applicable"],
        "assessment_completion_percent": progress["completion_percent"],
        "assessment_status": progress["status"],
        "authorization_total": authorization["total"],
        "authorization_completed": authorization["completed"],
        "authorization_needs_review": authorization["needs_review"],
        "authorization_planned": authorization["planned"],
        "authorization_in_progress": authorization["in_progress"],
        "authorization_blocked": authorization["blocked"],
        "authorization_finding_identified": authorization["finding_identified"],
        "authorization_completion_percent": authorization["completion_percent"],
        "authorization_status": authorization["status"],
    }



def _build_api_resource_groups(endpoints):
    """Group discovered API operations by resource path; metadata only."""
    import re

    groups = {}

    for endpoint in endpoints:
        try:
            parsed = urlsplit(endpoint.url or "")
        except (TypeError, ValueError):
            continue

        path = parsed.path or "/"
        lower_path = path.lower()
        endpoint_type = (endpoint.endpoint_type or "").lower()

        is_api = (
            lower_path == "/api"
            or lower_path.startswith("/api/")
            or lower_path == "/graphql"
            or lower_path.startswith("/graphql/")
            or "openapi" in endpoint_type
            or "api operation" in endpoint_type
            or "api endpoint" in endpoint_type
        )
        if not is_api:
            continue

        segments = [part for part in path.strip("/").split("/") if part]
        if not segments:
            continue

        # Normalize concrete identifiers without losing documented templates.
        normalized = []
        for segment in segments:
            if re.fullmatch(r"[0-9]+", segment):
                normalized.append("{id}")
            elif re.fullmatch(r"[0-9a-fA-F-]{32,36}", segment):
                normalized.append("{id}")
            else:
                normalized.append(segment)

        is_item_route = bool(
            normalized and normalized[-1].startswith("{")
            and normalized[-1].endswith("}")
        )

        # Collection and item routes belong to the same resource group.
        resource_segments = list(normalized)
        if is_item_route:
            resource_segments.pop()

        if not resource_segments:
            resource_segments = normalized

        resource_path = "/" + "/".join(resource_segments)
        method = (endpoint.method or "GET").upper()
        if method not in {
            "GET", "POST", "PUT", "PATCH",
            "DELETE", "OPTIONS", "HEAD",
        }:
            method = "OTHER"

        entry = groups.setdefault(resource_path, {
            "resource_path": resource_path,
            "resource": resource_segments[-1],
            "methods": set(),
            "collection_methods": set(),
            "item_methods": set(),
            "routes": [],
            "identifier_parameters": set(),
            "endpoint_ids": set(),
            "parent_resource": None,
        })

        entry["methods"].add(method)
        if is_item_route:
            entry["item_methods"].add(method)
        else:
            entry["collection_methods"].add(method)

        route = {
            "endpoint_id": endpoint.id,
            "method": method,
            "path": path,
            "is_item_route": is_item_route,
        }
        entry["routes"].append(route)
        entry["endpoint_ids"].add(endpoint.id)

        for match in re.findall(r"\{([^{}]+)\}", path):
            if match:
                entry["identifier_parameters"].add(match)

        # Include identity parameter names from previously extracted metadata.
        try:
            intelligence = analyze_endpoint(endpoint)
            for name in intelligence.get("identity_parameter_names", []):
                entry["identifier_parameters"].add(name)
        except Exception:
            pass

    result = []

    for entry in groups.values():
        collection = entry["collection_methods"]
        item = entry["item_methods"]

        missing = []
        if entry["routes"]:
            if collection:
                for method in ("GET", "POST"):
                    if method not in collection:
                        missing.append({
                            "route_type": "collection",
                            "method": method,
                        })
            if item:
                for method in ("GET", "PUT", "PATCH", "DELETE"):
                    if method not in item:
                        missing.append({
                            "route_type": "individual resource",
                            "method": method,
                        })

        parent = None
        parts = entry["resource_path"].strip("/").split("/")
        if len(parts) > 1:
            parent = "/" + "/".join(parts[:-1])

        identifier_names = {
            str(name).lower()
            for name in entry["identifier_parameters"]
        }

        ownership_markers = {
            "userid", "accountid", "customerid", "ownerid",
            "memberid", "profileid", "resourceid",
        }
        tenant_markers = {
            "tenantid", "organizationid", "orgid",
            "workspaceid", "companyid",
        }
        role_markers = {
            "roleid", "permissionid", "privilegeid",
        }
        privileged_routes = {
            "admin", "admins", "administrator",
            "administrators", "roles", "permissions", "privileges",
        }

        authorization_signals = []

        if identifier_names.intersection(ownership_markers):
            authorization_signals.append(
                "Object ownership and identifier authorization"
            )

        if identifier_names.intersection(tenant_markers):
            authorization_signals.append(
                "Tenant and organization isolation"
            )

        route_segments = [
            segment.lower()
            for route in entry["routes"]
            for segment in route["path"].strip("/").split("/")
            if segment
        ]

        if (
            identifier_names.intersection(role_markers)
            or any(segment in privileged_routes for segment in route_segments)
        ):
            authorization_signals.append(
                "Role and privileged-function authorization"
            )

        nested_resource = any(
            any(
                segment.startswith("{") and segment.endswith("}")
                for segment in route["path"].strip("/").split("/")[:-1]
            )
            for route in entry["routes"]
        )

        if nested_resource:
            authorization_signals.append(
                "Nested-resource parent-child authorization"
            )

        result.append({
            "resource_path": entry["resource_path"],
            "authorization_review_signals": sorted(set(authorization_signals)),
            "authorization_review_required": bool(authorization_signals),
            "resource": entry["resource"],
            "parent_resource": parent,
            "methods": sorted(entry["methods"]),
            "collection_methods": sorted(collection),
            "item_methods": sorted(item),
            "routes": sorted(
                entry["routes"],
                key=lambda route: (
                    route["path"], route["method"], route["endpoint_id"]
                ),
            ),
            "endpoint_count": len(entry["endpoint_ids"]),
            "identifier_parameters": sorted(
                entry["identifier_parameters"]
            ),
            "not_observed": missing,
            "review_note": (
                "Unobserved operations are inventory review suggestions, "
                "not evidence of a vulnerability."
            ),
        })

    return sorted(
        result,
        key=lambda group: group["resource_path"].lower()
    )



def get_project_coverage(db, project_id):
    project = db.get(Project, project_id)
    if not project or project.status == "deleted":
        raise ValueError("Project is unavailable.")

    assets = db.scalars(
        select(ScopeAsset).where(
            ScopeAsset.project_id == project_id,
            ScopeAsset.included.is_(True),
            ScopeAsset.approved.is_(True),
        ).order_by(ScopeAsset.host)
    ).all()

    checks = db.scalars(
        select(ScanCheck).where(
            ScanCheck.project_id == project_id
        ).order_by(ScanCheck.created_at.desc())
    ).all()

    endpoints = db.scalars(
        select(Endpoint).where(Endpoint.project_id == project_id)
    ).all()

    findings = db.scalars(
        select(Finding).where(Finding.project_id == project_id)
    ).all()

    jobs = db.scalars(
        select(AssessmentJob).where(
            AssessmentJob.project_id == project_id
        ).order_by(AssessmentJob.created_at.desc())
    ).all()

    tests = db.scalars(
        select(TestCase).where(
            TestCase.project_id == project_id
        ).order_by(TestCase.category, TestCase.id)
    ).all()

    endpoint_counts = Counter(_host(item.url) for item in endpoints)
    finding_counts = Counter(_host(item.asset) for item in findings)

    check_groups = {}
    for asset in assets:
        host = _host(asset.host)
        matching = [
            check for check in checks
            if _host(check.asset) == host and _is_assessment_check(check)
        ]
        check_groups[host] = {
            "total_checks": len(matching),
            "check_names": sorted({
                check.check_name for check in matching
            }),
            "last_check": (
                matching[0].created_at.isoformat()
                if matching and matching[0].created_at else None
            ),
            "outcomes": dict(Counter(
                check.outcome for check in matching
            )),
        }

    project_categories = _build_category_rows(tests)

    tests_by_endpoint = defaultdict(list)
    for test in tests:
        key = _endpoint_key(test.target)
        if key:
            tests_by_endpoint[key].append(test)

    endpoint_rows = []
    for endpoint in sorted(endpoints, key=lambda item: item.id):
        matching_tests = tests_by_endpoint.get(
            _endpoint_key(endpoint.url), []
        )
        progress = _endpoint_progress(matching_tests)
        intelligence = analyze_endpoint(endpoint)

        endpoint_rows.append({
            "endpoint_id": endpoint.id,
            "url": safe_endpoint_url(endpoint.url),
            "display_url": safe_endpoint_url(endpoint.url),
            **intelligence,
            "method": endpoint.method,
            "type": endpoint.endpoint_type,
            "notes": endpoint.notes,
            **progress,
            "categories": _build_category_rows(matching_tests),
            "test_cases": [
                {
                    "category": test.category,
                    "title": test.title,
                    "status": test.status,
                    "notes": test.notes,
                }
                for test in matching_tests
            ],
            "has_recommendations": bool(matching_tests),
        })

    api_resource_groups = _build_api_resource_groups(endpoints)
    from app.services.assessment_planner import build_assessment_scenarios
    assessment_scenarios = build_assessment_scenarios(endpoints)
    scenarios_by_endpoint = {}
    for scenario in assessment_scenarios:
        scenarios_by_endpoint.setdefault(scenario["endpoint_id"], []).append(scenario)

    # Match manual test cases to routes using normalized target URLs.
    endpoint_by_id = {
        endpoint.id: endpoint for endpoint in endpoints
    }
    tests_by_endpoint_key = {}

    for test in tests:
        key = _endpoint_key(test.target)
        if key:
            tests_by_endpoint_key.setdefault(key, []).append(test)

    for group in api_resource_groups:
        resource_tests = {}

        for route in group["routes"]:
            endpoint = endpoint_by_id.get(route["endpoint_id"])
            if endpoint is None:
                continue

            route_tests = tests_by_endpoint_key.get(
                _endpoint_key(endpoint.url), []
            )
            route_progress = _resource_assessment_progress(route_tests)

            route["assessment_progress"] = route_progress
            route["assessment_summary"] = (
                f"{route_progress['assessment_completed']}/"
                f"{route_progress['assessment_applicable']} completed; "
                f"{route_progress['assessment_needs_review']} review; "
                f"{route_progress['assessment_planned']} planned; "
                f"{route_progress['assessment_blocked']} blocked"
            )
            route["assessment_scenarios"] = scenarios_by_endpoint.get(
                route["endpoint_id"], []
            )
            route["authorization_summary"] = (
                f"{route_progress['authorization_completed']}/"
                f"{route_progress['authorization_total']} completed; "
                f"{route_progress['authorization_needs_review']} review"
            )

            for test in route_tests:
                resource_tests[test.id] = test

        unique_tests = list(resource_tests.values())
        progress = _resource_assessment_progress(unique_tests)
        group.update(progress)

        group["assessment_task_count"] = len(unique_tests)
        group["assessment_task_ids"] = sorted(resource_tests)

        group["assessment_summary"] = (
            f"{progress['assessment_completed']}/"
            f"{progress['assessment_applicable']} completed; "
            f"{progress['assessment_needs_review']} review; "
            f"{progress['assessment_planned']} planned; "
            f"{progress['assessment_in_progress']} in progress; "
            f"{progress['assessment_blocked']} blocked"
        )
        group["authorization_summary"] = (
            f"{progress['authorization_completed']}/"
            f"{progress['authorization_total']} completed; "
            f"{progress['authorization_needs_review']} review; "
            f"{progress['authorization_planned']} planned"
        )
        group["progress_note"] = (
            "Progress reflects recorded manual test cases matched by "
            "normalized endpoint URL. Routes sharing the same URL may share "
            "task counts because test cases do not store endpoint IDs. "
            "'Finding identified' requires evidence-based review and is not "
            "automatically a confirmed vulnerability."
        )

    endpoint_test_count = sum(
        item["total"] for item in endpoint_rows
    )
    endpoints_with_tests = sum(
        1 for item in endpoint_rows if item["has_recommendations"]
    )

    asset_rows = []
    assessed_count = 0

    for asset in assets:
        host = _host(asset.host)
        data = check_groups.get(host, {})
        count = data.get("total_checks", 0)
        if count:
            assessed_count += 1

        # Never assign an unscoped test case to an arbitrary asset.
        targeted_tests = [
            test for test in tests
            if test.target and _host(test.target) == host
        ]

        asset_rows.append({
            "asset_id": asset.id,
            "host": host,
            "assessment_status": "assessed" if count else "not_assessed",
            "checks_completed": count,
            "check_names": data.get("check_names", []),
            "last_check": data.get("last_check"),
            "outcomes": data.get("outcomes", {}),
            "endpoints_discovered": endpoint_counts.get(host, 0),
            "findings_recorded": finding_counts.get(host, 0),
            "test_cases_targeted": len(targeted_tests),
            "test_categories": _build_category_rows(targeted_tests),
        })

    total_assets = len(assets)
    status_counts = Counter(test.status for test in tests)
    completed = sum(status_counts[s] for s in COMPLETED)
    not_applicable = status_counts["Not applicable"]
    applicable = len(tests) - not_applicable

    return {
        "project_id": project_id,
        "project_name": project.name,
        "scope_approved": bool(project.scope_approved),
        "summary": {
            "approved_assets": total_assets,
            "assessed_assets": assessed_count,
            "unassessed_assets": total_assets - assessed_count,
            "asset_coverage_percent": (
                round(assessed_count / total_assets * 100, 2)
                if total_assets else 0
            ),
            "endpoints_discovered": len(endpoints),
            "endpoints_with_recommendations": endpoints_with_tests,
            "endpoints_without_recommendations": len(endpoints) - endpoints_with_tests,
            "endpoint_test_cases": endpoint_test_count,
            "api_resource_groups": len(api_resource_groups),
            "assessment_scenarios": len(assessment_scenarios),
            "api_resource_endpoints": sum(
                group["endpoint_count"] for group in api_resource_groups
            ),
            "checks_recorded": len(checks),
            "assessment_checks_recorded": sum(
                item["total_checks"] for item in check_groups.values()
            ),
            "findings_recorded": len(findings),
            "test_cases_total": len(tests),
            "test_cases_completed": completed,
            "test_cases_needs_review": status_counts["Needs review"],
            "test_cases_blocked": status_counts["Blocked"],
            "test_cases_not_applicable": not_applicable,
            "test_plan_completion_percent": (
                round(completed / applicable * 100, 2) if applicable else 0
            ),
            "unassigned_test_cases": sum(
                1 for test in tests if not test.target
            ),
        },
        "test_plan": project_categories,
        "endpoints": endpoint_rows,
        "api_resource_groups": api_resource_groups,
        "assessment_scenarios": assessment_scenarios,
        "assets": asset_rows,
        "recent_jobs": [
            {
                "id": job.id,
                "type": job.job_type,
                "status": job.status,
                "progress": job.progress,
                "created_at": (
                    job.created_at.isoformat() if job.created_at else None
                ),
            }
            for job in jobs[:20]
        ],
        "notice": (
            "Coverage measures recorded assessment activity, not proof "
            "that every vulnerability class was tested or that an asset "
            "is secure. Finding identified requires evidence-based review. "
            "Unassigned test cases count only toward project-level progress. "
            "Not applicable tests are excluded from completion calculations."
        ),
    }
