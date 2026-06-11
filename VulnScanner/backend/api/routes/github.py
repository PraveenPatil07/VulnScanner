"""GitHub repository scanning endpoint."""

import logging
import os
import re
import uuid

import httpx
import redis as sync_redis
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator

from ...worker.tasks import run_scan_task

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["github"])

REDIS_URL = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
_blob_redis = sync_redis.Redis.from_url(REDIS_URL)
ZIP_BLOB_TTL = 600

# Pattern to match GitHub repo URLs or shorthand owner/repo
_GITHUB_PATTERNS = [
    re.compile(r"^https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/?$"),
    re.compile(r"^(?P<owner>[a-zA-Z0-9_.-]+)/(?P<repo>[a-zA-Z0-9_.-]+)$"),
]

MAX_DOWNLOAD_SIZE = 200 * 1024 * 1024  # 200MB


class GitHubScanRequest(BaseModel):
    repo_url: str
    branch: str = "main"

    @field_validator("repo_url")
    @classmethod
    def validate_repo_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Repository URL is required")
        for pattern in _GITHUB_PATTERNS:
            if pattern.match(v):
                return v
        raise ValueError(
            "Invalid GitHub repository. Use 'owner/repo' or 'https://github.com/owner/repo'"
        )


def _parse_owner_repo(repo_url: str) -> tuple[str, str]:
    """Extract owner and repo name from URL or shorthand."""
    for pattern in _GITHUB_PATTERNS:
        m = pattern.match(repo_url.strip())
        if m:
            return m.group("owner"), m.group("repo")
    raise ValueError("Cannot parse repository URL")


@router.post("/scan/github")
async def scan_github_repo(request: GitHubScanRequest):
    """
    Scan a public GitHub repository by downloading its ZIP archive.

    Accepts GitHub URLs (https://github.com/owner/repo) or shorthand (owner/repo).
    Downloads the repository as a ZIP from GitHub's archive endpoint and
    feeds it into the existing scan pipeline.
    """
    owner, repo = _parse_owner_repo(request.repo_url)
    branch = request.branch.strip() or "main"

    # Sanitize branch name (prevent path traversal)
    if "/" in branch and not re.match(r"^[a-zA-Z0-9_./-]+$", branch):
        raise HTTPException(status_code=400, detail="Invalid branch name")

    zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.zip"

    # Download the ZIP archive
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=60.0) as client:
            response = await client.get(zip_url)

            if response.status_code == 404:
                raise HTTPException(
                    status_code=404,
                    detail=f"Repository '{owner}/{repo}' or branch '{branch}' not found on GitHub",
                )
            if response.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail=f"GitHub returned status {response.status_code}",
                )

            zip_bytes = response.content

            if len(zip_bytes) > MAX_DOWNLOAD_SIZE:
                raise HTTPException(
                    status_code=413,
                    detail="Repository archive exceeds 200MB limit",
                )
            if len(zip_bytes) == 0:
                raise HTTPException(
                    status_code=502,
                    detail="GitHub returned an empty archive",
                )

    except httpx.TimeoutException:
        raise HTTPException(
            status_code=504,
            detail="Timed out downloading repository from GitHub",
        )
    except httpx.RequestError as e:
        raise HTTPException(
            status_code=502,
            detail=f"Failed to connect to GitHub: {e}",
        )

    # Store in Redis and dispatch scan
    scan_id = str(uuid.uuid4())
    blob_key = f"scan:{scan_id}:zip"
    _blob_redis.set(blob_key, zip_bytes, ex=ZIP_BLOB_TTL)

    filename = f"{owner}-{repo}-{branch}.zip"

    run_scan_task.apply_async(
        args=[scan_id, blob_key, filename],
        task_id=scan_id,
    )

    return {
        "scan_id": scan_id,
        "status": "QUEUED",
        "filename": filename,
        "repo": f"{owner}/{repo}",
        "branch": branch,
    }
