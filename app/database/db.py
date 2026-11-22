from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, DeclarativeBase, Session, with_loader_criteria
from sqlalchemy import event, select
from app.core.config import DATABASE_URL
class Base(DeclarativeBase): pass
_connect_args = {"check_same_thread": False, "timeout": 30} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=_connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


if engine.dialect.name == "sqlite":
    @event.listens_for(engine, "connect")
    def _set_sqlite_busy_timeout(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.close()


@event.listens_for(Session, "do_orm_execute")
def _enforce_account_project_isolation(execute_state):
    """Restrict ORM project reads and bulk writes to the active account."""
    from app.models.entities import Project, User

    session = execute_state.session
    owner_id = session.info.get("owner_id", -1)

    statement = execute_state.statement.options(
        with_loader_criteria(
            Project,
            lambda model: model.owner_id == owner_id,
            include_aliases=True,
        )
    )

    # Every project-linked ORM model is restricted through its project.
    for mapper in Base.registry.mappers:
        model = mapper.class_
        if model in (Project, User) or not hasattr(model, "project_id"):
            continue

        statement = statement.options(
            with_loader_criteria(
                model,
                lambda cls: cls.project_id.in_(
                    select(Project.id).where(Project.owner_id == owner_id)
                ),
                include_aliases=True,
            )
        )

    execute_state.statement = statement


@event.listens_for(Session, "before_flush")
def _validate_account_project_writes(session, flush_context, instances):
    """Reject project and child-record writes outside the logged-in account."""
    from app.models.entities import Project, User

    owner_id = session.info.get("owner_id")
    candidates = set(session.new) | set(session.dirty) | set(session.deleted)

    for obj in candidates:
        if isinstance(obj, User):
            continue

        if isinstance(obj, Project):
            if not isinstance(owner_id, int) or owner_id <= 0:
                raise PermissionError("An authenticated account is required.")
            if obj.owner_id != owner_id:
                raise PermissionError("Cannot modify another account's project.")
            continue

        if not hasattr(obj, "project_id"):
            continue

        if not isinstance(owner_id, int) or owner_id <= 0:
            raise PermissionError("An authenticated account is required.")

        project_id = getattr(obj, "project_id", None)
        if project_id is None:
            raise PermissionError("A project-linked record requires a project.")

        # Use the current transaction connection to verify ownership.
        # This also protects updates and deletes of existing child records.
        result = session.connection().execute(
            text("SELECT owner_id FROM projects WHERE id = :project_id"),
            {"project_id": project_id},
        ).first()

        if result is None or result[0] != owner_id:
            raise PermissionError(
                "Cannot create, modify, or delete records belonging to another account."
            )


def init_db():
    from app.models import entities

    if engine.dialect.name == "sqlite":
        with engine.connect() as connection:
            connection.exec_driver_sql("PRAGMA journal_mode=WAL")
            connection.commit()

    Base.metadata.create_all(bind=engine)

    # Durable input for independent background hunt jobs.
    job_columns = {
        column["name"]
        for column in inspect(engine).get_columns("assessment_jobs")
    }
    if "input_json" not in job_columns:
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "ALTER TABLE assessment_jobs ADD COLUMN "
                "input_json TEXT NOT NULL DEFAULT '{}'"
            )

    # Add project ownership to existing installations.
    project_columns = {
        column["name"]
        for column in inspect(engine).get_columns("projects")
    }

    with engine.begin() as connection:
        if "owner_id" not in project_columns:
            connection.exec_driver_sql(
                "ALTER TABLE projects ADD COLUMN owner_id INTEGER"
            )

        users = connection.exec_driver_sql(
            "SELECT id FROM users ORDER BY id"
        ).fetchall()

        unassigned = connection.exec_driver_sql(
            "SELECT COUNT(*) FROM projects WHERE owner_id IS NULL"
        ).scalar_one()

        if unassigned:
            if len(users) != 1:
                raise RuntimeError(
                    "Cannot automatically assign existing projects: "
                    "the database must have exactly one user account. "
                    "No project ownership was guessed."
                )
            if engine.dialect.name == "sqlite":
                connection.exec_driver_sql(
                    "UPDATE projects SET owner_id = ? WHERE owner_id IS NULL",
                    (users[0][0],),
                )
            else:
                connection.execute(
                    text("UPDATE projects SET owner_id = :owner_id WHERE owner_id IS NULL"),
                    {"owner_id": users[0][0]},
                )

        connection.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_projects_owner_id ON projects (owner_id)"
        )

    # Add candidate-review fields without changing existing policy evidence.
    asset_columns = {
        column["name"]
        for column in inspect(engine).get_columns("program_assets")
    }

    with engine.begin() as connection:
        migrations = {
            "review_status": (
                "ALTER TABLE program_assets ADD COLUMN "
                "review_status VARCHAR(40) NOT NULL DEFAULT 'pending'"
            ),
            "review_note": (
                "ALTER TABLE program_assets ADD COLUMN "
                "review_note TEXT NOT NULL DEFAULT ''"
            ),
            "reviewed_at": (
                "ALTER TABLE program_assets ADD COLUMN reviewed_at TIMESTAMP"
            ),
            "reviewed_by_user_id": (
                "ALTER TABLE program_assets ADD COLUMN "
                "reviewed_by_user_id INTEGER"
            ),
        }
        for column_name, statement in migrations.items():
            if column_name not in asset_columns:
                connection.exec_driver_sql(statement)

    # Add nullable evidence links without changing existing records.
    columns = {
        column["name"]
        for column in inspect(engine).get_columns("evidence")
    }

    with engine.begin() as connection:
        if "test_case_id" not in columns:
            connection.exec_driver_sql(
                "ALTER TABLE evidence ADD COLUMN test_case_id INTEGER"
            )

        if "scan_check_id" not in columns:
            connection.exec_driver_sql(
                "ALTER TABLE evidence ADD COLUMN scan_check_id INTEGER"
            )

        if engine.dialect.name in {"sqlite", "postgresql"}:
            connection.exec_driver_sql(
                "CREATE INDEX IF NOT EXISTS ix_evidence_test_case_id "
                "ON evidence (test_case_id)"
            )
            connection.exec_driver_sql(
                "CREATE INDEX IF NOT EXISTS ix_evidence_scan_check_id "
                "ON evidence (scan_check_id)"
            )
