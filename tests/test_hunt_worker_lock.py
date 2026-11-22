from types import SimpleNamespace

from app.services import hunt_daemon


def test_sqlite_worker_lock_is_exclusive_and_released(tmp_path, monkeypatch):
    monkeypatch.setattr(hunt_daemon, "DATA_DIR", tmp_path)
    monkeypatch.setattr(
        hunt_daemon,
        "engine",
        SimpleNamespace(dialect=SimpleNamespace(name="sqlite")),
    )

    first = hunt_daemon.acquire_worker_lock()
    assert first is not None
    assert (tmp_path / "hunt-worker.lock").exists()
    assert hunt_daemon.acquire_worker_lock() is None

    first.release()
    second = hunt_daemon.acquire_worker_lock()
    assert second is not None
    second.release()


def test_postgres_worker_lock_uses_session_advisory_lock(monkeypatch):
    calls = []

    class Result:
        def scalar_one(self):
            return True

    class Connection:
        def execute(self, statement, params):
            calls.append((str(statement), params))
            return Result()

        def close(self):
            calls.append(("close", None))

    connection = Connection()
    fake_engine = SimpleNamespace(
        dialect=SimpleNamespace(name="postgresql"),
        connect=lambda: connection,
    )
    monkeypatch.setattr(hunt_daemon, "engine", fake_engine)

    lock = hunt_daemon.acquire_worker_lock()
    assert lock is not None
    assert calls[0][1] == {"key": 731946205118}

    lock.release()
    assert "pg_advisory_unlock" in calls[1][0]
    assert calls[2] == ("close", None)


def test_postgres_worker_lock_returns_none_when_another_worker_owns_it(
    monkeypatch,
):
    class Result:
        def scalar_one(self):
            return False

    class Connection:
        closed = False

        def execute(self, statement, params):
            return Result()

        def close(self):
            self.closed = True

    connection = Connection()
    fake_engine = SimpleNamespace(
        dialect=SimpleNamespace(name="postgresql"),
        connect=lambda: connection,
    )
    monkeypatch.setattr(hunt_daemon, "engine", fake_engine)

    assert hunt_daemon.acquire_worker_lock() is None
    assert connection.closed
