"""
Authenticated HTTP client for the central BugHunter AI API.

Tokens remain in memory. This module does not persist credentials or tokens.
"""

from urllib.parse import quote

import httpx

from app.core.config import API_BASE_URL, API_TIMEOUT


class APIError(Exception):
    def __init__(self, status_code, detail):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"API error {status_code}: {detail}")


class APIClient:
    PROJECT_RESOURCES = {
        "assets",
        "findings",
        "reviews",
        "activities",
        "checks",
        "endpoints",
        "test-cases",
        "evidence",
        "jobs",
    }

    def __init__(self, base_url=None, timeout=None):
        self.base_url = (base_url or API_BASE_URL).rstrip("/")
        self.timeout = API_TIMEOUT if timeout is None else timeout
        self._token = None
        self._http = httpx.Client(
            base_url=self.base_url,
            timeout=self.timeout,
            trust_env=False,
            headers={"Accept": "application/json"},
        )

    @property
    def authenticated(self):
        return bool(self._token)

    def close(self):
        self._token = None
        self._http.close()

    def logout(self):
        self._token = None

    def request(self, method, path, *, params=None, json_data=None):
        headers = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        try:
            response = self._http.request(
                method,
                path,
                params=params,
                json=json_data,
                headers=headers,
            )
        except httpx.TimeoutException as exc:
            raise APIError(0, "The API request timed out.") from exc
        except httpx.RequestError as exc:
            raise APIError(
                0,
                f"Cannot connect to BugHunter AI API at {self.base_url}.",
            ) from exc

        if response.status_code >= 400:
            try:
                body = response.json()
                detail = body.get("detail", body)
            except ValueError:
                detail = response.text[:500] or "Request failed."
            raise APIError(response.status_code, detail)

        if response.status_code == 204 or not response.content:
            return None

        try:
            return response.json()
        except ValueError as exc:
            raise APIError(
                response.status_code,
                "The API returned an invalid JSON response.",
            ) from exc

    def login(self, username, password):
        result = self.request(
            "POST",
            "/api/v1/auth/login",
            json_data={
                "username": username.strip(),
                "password": password,
            },
        )
        token = result.get("access_token") if isinstance(result, dict) else None
        if not token:
            raise APIError(502, "Login response did not contain an access token.")

        self._token = token
        return result

    def me(self):
        return self.request("GET", "/api/v1/me")

    def list_projects(self):
        return self.request("GET", "/api/v1/projects")

    def create_project(self, name, programme_url=""):
        return self.request(
            "POST",
            "/api/v1/projects",
            json_data={
                "name": name,
                "programme_url": programme_url,
            },
        )

    def get_project(self, project_id):
        return self.request("GET", f"/api/v1/projects/{int(project_id)}")

    def list_project_resource(self, project_id, resource):
        if resource not in self.PROJECT_RESOURCES:
            raise ValueError(f"Unsupported project resource: {resource}")
        return self.request(
            "GET",
            f"/api/v1/projects/{int(project_id)}/{resource}",
        )

    def start_hunt(self, project_id, start_url, max_pages=25):
        return self.request(
            "POST",
            f"/api/v1/projects/{int(project_id)}/hunts",
            json_data={
                "start_url": start_url,
                "max_pages": max_pages,
            },
        )

    def archive_project(self, project_id, confirmation_name):
        return self.request(
            "POST",
            f"/api/v1/projects/{int(project_id)}/archive",
            json_data={"confirmation_name": confirmation_name},
        )

    def restore_project(self, project_id, confirmation_name):
        return self.request(
            "POST",
            f"/api/v1/projects/{int(project_id)}/restore",
            json_data={"confirmation_name": confirmation_name},
        )

    def add_scope_asset(self, project_id, host, included=True, notes=""):
        return self.request(
            "POST",
            f"/api/v1/projects/{int(project_id)}/assets",
            json_data={
                "host": host,
                "included": included,
                "notes": notes,
            },
        )

    def approve_scope(self, project_id, policy_text):
        return self.request(
            "POST",
            f"/api/v1/projects/{int(project_id)}/approve-scope",
            json_data={"policy_text": policy_text},
        )

    def add_endpoint(self, project_id, url, endpoint_type, method="GET", notes=""):
        return self.request(
            "POST",
            f"/api/v1/projects/{int(project_id)}/endpoints",
            json_data={
                "url": url,
                "endpoint_type": endpoint_type,
                "method": method,
                "notes": notes,
            },
        )

    def initialize_test_plan(self, project_id):
        return self.request(
            "POST",
            f"/api/v1/projects/{int(project_id)}/initialize-test-plan",
        )

    def update_test_case(self, project_id, test_id, status, target=None, notes=None):
        data = {"status": status}
        if target is not None:
            data["target"] = target
        if notes is not None:
            data["notes"] = notes
        return self.request(
            "PATCH",
            f"/api/v1/projects/{int(project_id)}/test-cases/{int(test_id)}",
            json_data=data,
        )

    def analyze_program(self, project_id, policy_text=""):
        return self.request(
            "POST",
            f"/api/v1/projects/{int(project_id)}/analyze-program",
            json_data={"policy_text": policy_text},
        )

    def list_program_policies(self, project_id):
        return self.request(
            "GET",
            f"/api/v1/projects/{int(project_id)}/program-policies",
        )

    def review_program_asset(self, project_id, asset_id, decision, note=""):
        return self.request(
            "PATCH",
            f"/api/v1/projects/{int(project_id)}/program-assets/{int(asset_id)}/review",
            json_data={"decision": decision, "note": note},
        )

    def add_program_asset_to_scope(self, project_id, asset_id):
        return self.request(
            "POST",
            f"/api/v1/projects/{int(project_id)}/program-assets/{int(asset_id)}/add-to-scope",
        )

    def review_finding(self, project_id, finding_id, **changes):
        return self.request(
            "PATCH",
            f"/api/v1/projects/{int(project_id)}/findings/{int(finding_id)}",
            json_data=changes,
        )
