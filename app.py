"""Resumable GitHub Actions research-data collector.

Raw outcomes are stored for auditability. Feature engineering later enforces the
pre-execution cutoff defined in docs/research_protocol.md.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import secrets
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

import requests
from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "configs" / "research.json"
DEFAULT_REPOSITORIES = ROOT / "configs" / "repositories.txt"
DEFAULT_DATABASE = ROOT / "data" / "research" / "buildrisk.sqlite3"
DEFAULT_SALT_FILE = ROOT / "data" / "research" / ".hash_salt"
SCHEMA = Path(__file__).with_name("schema.sql")
API_ROOT = "https://api.github.com"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def pseudonym(value: str | None, salt: str, namespace: str) -> str | None:
    if not value:
        return None
    payload = f"{namespace}:{value}:{salt}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def file_extension(filename: str) -> str:
    name = Path(filename).name
    if name.startswith(".") and name.count(".") == 1:
        return name.lower()
    return Path(filename).suffix.lower()


def load_or_create_salt(path: Path) -> str:
    environment_salt = os.getenv("BUILDRISK_HASH_SALT", "").strip()
    if environment_salt:
        return environment_salt
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    path.parent.mkdir(parents=True, exist_ok=True)
    value = secrets.token_hex(32)
    path.write_text(value, encoding="utf-8")
    return value


class GitHubClient:
    def __init__(self, token: str, timeout: int, retries: int, backoff: int):
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "BuildRisk-Research-Collector/1.0",
            }
        )
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"

    def get(self, path: str, params: dict | None = None) -> requests.Response:
        url = path if path.startswith("http") else f"{API_ROOT}{path}"
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                response = self.session.get(url, params=params, timeout=self.timeout)
            except requests.RequestException as error:
                last_error = error
                if attempt == self.retries:
                    raise
                self._sleep(attempt)
                continue

            if response.status_code == 403 and response.headers.get("X-RateLimit-Remaining") == "0":
                reset = int(response.headers.get("X-RateLimit-Reset", "0"))
                wait = max(1, reset - int(time.time()) + 1)
                time.sleep(min(wait, 900))
                continue
            if response.status_code in {429, 500, 502, 503, 504}:
                if attempt == self.retries:
                    response.raise_for_status()
                retry_after = response.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    time.sleep(min(int(retry_after), 120))
                else:
                    self._sleep(attempt)
                continue
            response.raise_for_status()
            return response
        raise RuntimeError(f"GitHub request failed: {url}") from last_error

    def _sleep(self, attempt: int) -> None:
        delay = self.backoff * (2**attempt) + random.random()
        time.sleep(min(delay, 120))

    def pages(self, path: str, params: dict | None = None) -> Iterator[dict]:
        query = dict(params or {})
        query.setdefault("per_page", 100)
        page = 1
        while True:
            query["page"] = page
            response = self.get(path, query)
            payload = response.json()
            yield payload
            if "next" not in response.links:
                return
            page += 1


class Collector:
    def __init__(self, database: Path, client: GitHubClient, salt: str, cutoff: datetime):
        database.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(database)
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self.connection.executescript(SCHEMA.read_text(encoding="utf-8"))
        self.client = client
        self.salt = salt
        self.cutoff = cutoff

    def close(self) -> None:
        self.connection.close()

    def record_error(
        self,
        repository: str,
        entity_type: str,
        entity_id: str,
        error: Exception,
    ) -> None:
        status_code = getattr(getattr(error, "response", None), "status_code", None)
        self.connection.execute(
            "INSERT INTO collection_errors "
            "(repository, entity_type, entity_id, status_code, message, occurred_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (repository, entity_type, entity_id, status_code, str(error)[:2000], utc_now()),
        )
        self.connection.commit()

    def collect_repository(self, repository: str, include_jobs: bool) -> None:
        print(f"Collecting {repository}")
        try:
            metadata = self.client.get(f"/repos/{repository}").json()
            self._upsert_repository(repository, metadata)
            self._collect_workflows(repository)
            commits, runs = self._collect_runs(repository)
            for commit_id in sorted(commits):
                self._collect_commit(repository, commit_id)
            if include_jobs:
                for run_id, run_attempt in sorted(runs):
                    self._collect_jobs(repository, run_id, run_attempt)
            self.connection.commit()
        except (requests.RequestException, ValueError, KeyError, sqlite3.DatabaseError) as error:
            self.record_error(repository, "repository", repository, error)
            print(f"  failed: {error}", file=sys.stderr)

    def _upsert_repository(self, repository: str, data: dict) -> None:
        self.connection.execute(
            "INSERT INTO repositories "
            "(repository, github_id, primary_language, stars, forks, size_kb, "
            "created_at, updated_at, default_branch, archived, is_fork, collected_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(repository) DO UPDATE SET "
            "github_id=excluded.github_id, primary_language=excluded.primary_language, "
            "stars=excluded.stars, forks=excluded.forks, size_kb=excluded.size_kb, "
            "updated_at=excluded.updated_at, default_branch=excluded.default_branch, "
            "archived=excluded.archived, is_fork=excluded.is_fork, "
            "collected_at=excluded.collected_at",
            (
                repository,
                data.get("id"),
                data.get("language"),
                data.get("stargazers_count"),
                data.get("forks_count"),
                data.get("size"),
                data.get("created_at"),
                data.get("updated_at"),
                data.get("default_branch"),
                int(bool(data.get("archived"))),
                int(bool(data.get("fork"))),
                utc_now(),
            ),
        )
        self.connection.commit()

    def _collect_workflows(self, repository: str) -> None:
        for payload in self.client.pages(f"/repos/{repository}/actions/workflows"):
            for item in payload.get("workflows", []):
                self.connection.execute(
                    "INSERT INTO workflows "
                    "(repository, workflow_id, workflow_name, workflow_path, workflow_state, "
                    "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(repository, workflow_id) DO UPDATE SET "
                    "workflow_name=excluded.workflow_name, workflow_path=excluded.workflow_path, "
                    "workflow_state=excluded.workflow_state, updated_at=excluded.updated_at",
                    (
                        repository,
                        item["id"],
                        item.get("name"),
                        item.get("path"),
                        item.get("state"),
                        item.get("created_at"),
                        item.get("updated_at"),
                    ),
                )

    def _collect_runs(self, repository: str) -> tuple[set[str], set[tuple[int, int]]]:
        commits: set[str] = set()
        runs: set[tuple[int, int]] = set()
        stop = False
        for payload in self.client.pages(f"/repos/{repository}/actions/runs"):
            for item in payload.get("workflow_runs", []):
                created_text = item.get("created_at")
                if created_text:
                    created = datetime.fromisoformat(created_text.replace("Z", "+00:00"))
                    if created < self.cutoff:
                        stop = True
                        break
                commit_id = item.get("head_sha")
                attempt = int(item.get("run_attempt") or 1)
                actor = (item.get("actor") or {}).get("login")
                self.connection.execute(
                    "INSERT INTO workflow_runs "
                    "(repository, run_id, run_attempt, workflow_id, workflow_name, workflow_path, "
                    "commit_id, branch, event, run_number, status, conclusion, created_at, "
                    "run_started_at, updated_at, actor_hash, collected_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(repository, run_id, run_attempt) DO UPDATE SET "
                    "status=excluded.status, conclusion=excluded.conclusion, "
                    "updated_at=excluded.updated_at, collected_at=excluded.collected_at",
                    (
                        repository,
                        item["id"],
                        attempt,
                        item.get("workflow_id"),
                        item.get("name"),
                        item.get("path"),
                        commit_id,
                        item.get("head_branch"),
                        item.get("event"),
                        item.get("run_number"),
                        item.get("status"),
                        item.get("conclusion"),
                        created_text,
                        item.get("run_started_at"),
                        item.get("updated_at"),
                        pseudonym(actor, self.salt, repository),
                        utc_now(),
                    ),
                )
                if commit_id:
                    commits.add(commit_id)
                if item.get("conclusion") in {"success", "failure"}:
                    runs.add((int(item["id"]), attempt))
            self.connection.commit()
            if stop:
                break
        return commits, runs

    def _collect_commit(self, repository: str, commit_id: str) -> None:
        exists = self.connection.execute(
            "SELECT 1 FROM commits WHERE repository=? AND commit_id=?",
            (repository, commit_id),
        ).fetchone()
        if exists:
            return
        try:
            response = self.client.get(
                f"/repos/{repository}/commits/{commit_id}",
                {"per_page": 100, "page": 1},
            )
            data = response.json()
            files = list(data.get("files", []))
            next_url = response.links.get("next", {}).get("url")
            while next_url:
                response = self.client.get(next_url)
                page = response.json()
                files.extend(page.get("files", []))
                next_url = response.links.get("next", {}).get("url")
            commit = data.get("commit") or {}
            author = data.get("author") or {}
            author_key = author.get("login") or (commit.get("author") or {}).get("email")
            stats = data.get("stats") or {}
            parents = data.get("parents") or []
            message = commit.get("message") or ""
            self.connection.execute(
                "INSERT OR IGNORE INTO commits "
                "(repository, commit_id, author_hash, author_date, commit_date, message_length, "
                "is_merge, parent_count, files_changed, lines_added, lines_deleted, collected_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    repository,
                    commit_id,
                    pseudonym(author_key, self.salt, repository),
                    (commit.get("author") or {}).get("date"),
                    (commit.get("committer") or {}).get("date"),
                    len(message),
                    int(len(parents) > 1),
                    len(parents),
                    len(files),
                    stats.get("additions", 0),
                    stats.get("deletions", 0),
                    utc_now(),
                ),
            )
            for item in files:
                filename = item.get("filename")
                if not filename:
                    continue
                self.connection.execute(
                    "INSERT OR REPLACE INTO changed_files "
                    "(repository, commit_id, filename, extension, change_status, additions, "
                    "deletions, changes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        repository,
                        commit_id,
                        filename,
                        file_extension(filename),
                        item.get("status"),
                        item.get("additions"),
                        item.get("deletions"),
                        item.get("changes"),
                    ),
                )
            self.connection.commit()
        except (requests.RequestException, ValueError, KeyError) as error:
            self.record_error(repository, "commit", commit_id, error)

    def _collect_jobs(self, repository: str, run_id: int, attempt: int) -> None:
        try:
            path = f"/repos/{repository}/actions/runs/{run_id}/attempts/{attempt}/jobs"
            for payload in self.client.pages(path):
                for job in payload.get("jobs", []):
                    failed_step = next(
                        (
                            step.get("name")
                            for step in job.get("steps", [])
                            if step.get("conclusion") == "failure"
                        ),
                        None,
                    )
                    labels = job.get("labels") or []
                    runner_os = next(
                        (label for label in labels if label in {"Linux", "Windows", "macOS"}),
                        None,
                    )
                    self.connection.execute(
                        "INSERT OR REPLACE INTO workflow_jobs "
                        "(repository, run_id, run_attempt, job_id, job_name, runner_os, status, "
                        "conclusion, started_at, completed_at, failed_step) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            repository,
                            run_id,
                            attempt,
                            job["id"],
                            job.get("name"),
                            runner_os,
                            job.get("status"),
                            job.get("conclusion"),
                            job.get("started_at"),
                            job.get("completed_at"),
                            failed_step,
                        ),
                    )
            self.connection.commit()
        except (requests.RequestException, ValueError, KeyError) as error:
            self.record_error(repository, "workflow_jobs", str(run_id), error)


def load_repositories(path: Path) -> list[str]:
    repositories = []
    for line in path.read_text(encoding="utf-8").splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if value.count("/") != 1:
            raise ValueError(f"Invalid owner/repository entry: {value}")
        repositories.append(value)
    return sorted(set(repositories))


def main() -> int:
    load_dotenv(ROOT / ".env")
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--repositories", type=Path, default=DEFAULT_REPOSITORIES)
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    parser.add_argument("--include-jobs", action="store_true")
    parser.add_argument(
        "--repository",
        action="append",
        help="Collect only this owner/repository; may be provided multiple times.",
    )
    args = parser.parse_args()

    config = json.loads(args.config.read_text(encoding="utf-8"))
    collection = config["collection"]
    token = os.getenv("GITHUB_TOKEN", "")
    salt = load_or_create_salt(DEFAULT_SALT_FILE)
    if not token:
        print("Warning: GITHUB_TOKEN is unset; public API rate limits are low.", file=sys.stderr)

    cutoff = datetime.now(timezone.utc) - timedelta(days=30 * collection["months_of_history"])
    client = GitHubClient(
        token=token,
        timeout=collection["request_timeout_seconds"],
        retries=collection["maximum_retries"],
        backoff=collection["retry_backoff_seconds"],
    )
    collector = Collector(args.database.resolve(), client, salt, cutoff)
    try:
        repositories = args.repository or load_repositories(args.repositories.resolve())
        for repository in sorted(set(repositories)):
            collector.collect_repository(repository, args.include_jobs)
    finally:
        collector.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
