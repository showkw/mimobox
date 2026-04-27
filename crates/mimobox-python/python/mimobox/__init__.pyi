"""MimoBox — Local Sandbox Runtime for AI Agents. Run AI-generated code safely, locally, and instantly."""

from typing import Dict, Iterator, List, Optional, Union


class ExecuteResult:
    """Result of a sandbox command execution.

    Attributes:
        stdout: Standard output as a UTF-8 string (lossy decoded).
        stderr: Standard error as a UTF-8 string (lossy decoded).
        exit_code: Process exit code. -1 when unavailable (e.g., timeout).
        timed_out: Whether the command exceeded its time limit.
    """
    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool
    elapsed: Optional[float]


class DirEntry:
    """A single directory entry returned by ``Sandbox.list_dir()``.

    Attributes:
        name: File or directory name.
        file_type: Type string: ``"file"``, ``"dir"``, ``"symlink"``, or ``"other"``.
        size: File size in bytes.
        is_symlink: Whether this entry is a symbolic link.
    """

    name: str
    file_type: str
    size: int
    is_symlink: bool


class FileStat:
    """File metadata returned by ``Sandbox.stat()`` and ``Sandbox.fs.stat()``."""

    path: str
    is_dir: bool
    is_file: bool
    size: int
    mode: int
    modified_ms: Optional[int]


class HttpResponse:
    """HTTP response from the host-side proxy.

    Attributes:
        status: HTTP status code (e.g., 200, 404).
        headers: Response headers as a dictionary.
        body: Response body as raw bytes.
    """
    status: int

    @property
    def headers(self) -> Dict[str, str]: ...

    @property
    def body(self) -> bytes: ...


class Snapshot:
    """An immutable sandbox snapshot that can be saved and restored.

    Snapshots capture the complete sandbox state and can be used to create
    new sandbox instances via ``Sandbox.from_snapshot()``.
    """

    @classmethod
    def from_bytes(cls, data: bytes) -> "Snapshot":
        """Reconstruct a snapshot from its serialized byte representation.

        Args:
            data: Raw bytes previously obtained via ``to_bytes()``.

        Returns:
            A restored ``Snapshot`` instance.
        """
        ...

    @classmethod
    def from_file(cls, path: str) -> "Snapshot":
        """Create a Snapshot instance from a file-backed snapshot.

        Constructs a snapshot reference directly from the on-disk file path
        without loading the entire file into memory. This is useful for large
        snapshot files previously saved to disk via ``to_bytes()``.

        Args:
            path: On-disk path to the snapshot file.

        Returns:
            A restored ``Snapshot`` instance.

        Raises:
            FileNotFoundError: If the file does not exist.
            SandboxError: If the snapshot file is invalid.
        """
        ...

    def to_bytes(self) -> bytes:
        """Serialize the snapshot to raw bytes.

        Returns:
            The snapshot data as bytes.
        """
        ...

    @property
    def size(self) -> int:
        """Size of the snapshot data in bytes."""
        ...


class StreamEvent:
    """A single event from a streaming sandbox execution.

    Attributes:
        stdout: Stdout bytes chunk, or ``None`` if this event carries no stdout data.
        stderr: Stderr bytes chunk, or ``None`` if this event carries no stderr data.
        exit_code: Process exit code, or ``None`` if the process has not exited yet.
        timed_out: ``True`` if the command exceeded its time limit.
    """

    @property
    def stdout(self) -> Optional[bytes]: ...

    @property
    def stderr(self) -> Optional[bytes]: ...

    @property
    def exit_code(self) -> Optional[int]: ...

    @property
    def timed_out(self) -> bool: ...

    @property
    def event_type(self) -> str: ...


class StreamIterator:
    """Python iterator over ``StreamEvent`` objects from a streaming execution."""

    def __iter__(self) -> "StreamIterator": ...
    def __next__(self) -> Optional[StreamEvent]: ...


class FileSystem:
    def read(self, path: str) -> bytes: ...
    def write(self, path: str, data: Union[str, bytes]) -> None: ...
    def list(self, path: str) -> List[DirEntry]: ...
    def exists(self, path: str) -> bool: ...
    def remove(self, path: str) -> None: ...
    def rename(self, from: str, to: str) -> None: ...
    def stat(self, path: str) -> FileStat: ...


class Process:
    def run(
        self,
        command: str,
        env: Optional[Dict[str, str]] = ...,
        timeout: Optional[float] = ...,
        cwd: Optional[str] = ...,
    ) -> ExecuteResult: ...
    def run_code(
        self,
        language: str,
        code: str,
        *,
        env: Optional[Dict[str, str]] = ...,
        timeout: Optional[float] = ...,
        cwd: Optional[str] = ...,
    ) -> ExecuteResult: ...
    def stream(self, command: str) -> StreamIterator: ...


class SnapshotOps:
    def __call__(self) -> Snapshot: ...
    def capture(self) -> Snapshot: ...
    def fork(self) -> "Sandbox": ...


class Network:
    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = ...,
        body: Optional[bytes] = ...,
    ) -> HttpResponse: ...


class Sandbox:
    """A secure sandbox for executing commands.

    Usage::

        with Sandbox(isolation="os", allowed_http_domains=["api.example.com"]) as sb:
            result = sb.execute("echo hello", timeout=5.0)
            print(result.stdout)

    Args:
        isolation: Isolation level. One of ``"auto"``, ``"os"``, ``"wasm"``,
            ``"microvm"``. Defaults to ``"auto"`` (smart routing).
        allowed_http_domains: List of domains allowed for HTTP proxy requests.
            Supports glob patterns like ``"*.openai.com"``.
    """

    def __init__(
        self,
        *,
        isolation: Optional[str] = ...,
        allowed_http_domains: Optional[List[str]] = ...,
    ) -> None: ...

    @property
    def fs(self) -> FileSystem: ...

    @property
    def process(self) -> Process: ...

    @property
    def snapshot(self) -> SnapshotOps: ...

    @property
    def network(self) -> Network: ...

    def execute(
        self,
        command: str,
        env: Optional[Dict[str, str]] = ...,
        timeout: Optional[float] = ...,
        cwd: Optional[str] = ...,
    ) -> ExecuteResult:
        """Execute a shell-style command inside the sandbox.

        Args:
            command: Shell command to execute.
            env: Optional environment variables to set for the command.
            timeout: Optional timeout in seconds (float). Must be > 0 and finite.
            cwd: Optional working directory for the command.

        Returns:
            An ``ExecuteResult`` with stdout, stderr, exit_code, and timed_out.

        Raises:
            SandboxError: If the sandbox is destroyed or execution fails.
            SandboxProcessError: If the command exits non-zero or is killed.
        """
        ...

    def execute_code(
        self,
        language: str,
        code: str,
        *,
        env: Optional[Dict[str, str]] = ...,
        timeout: Optional[float] = ...,
        cwd: Optional[str] = ...,
    ) -> ExecuteResult:
        """Execute code in the given language inside the sandbox.

        Supported languages: ``"bash"``, ``"sh"``, ``"python"``, ``"python3"``,
        ``"py"``, ``"javascript"``, ``"js"``, ``"node"``, ``"nodejs"``.

        Args:
            language: Programming language name.
            code: Source code to execute.
            env: Optional environment variables to set for the command.
            timeout: Optional timeout in seconds (float). Must be > 0 and finite.
            cwd: Optional working directory for the command.

        Returns:
            An ``ExecuteResult`` with stdout, stderr, exit_code, and timed_out.

        Raises:
            SandboxError: If the sandbox is destroyed or execution fails.
            ValueError: If the language is not supported.
        """
        ...

    def stream_execute(self, command: str) -> StreamIterator:
        """Execute a command and return a streaming iterator of events.

        Args:
            command: Shell command to execute.

        Returns:
            A ``StreamIterator`` yielding ``StreamEvent`` objects for stdout,
            stderr chunks and the final exit event.
        """
        ...

    def wait_ready(self, timeout_secs: Optional[float] = ...) -> None:
        """Wait until the sandbox is ready to accept commands.

        Blocks until the underlying backend signals readiness (e.g. via PING/PONG
        for the microVM backend), or the timeout expires.

        Args:
            timeout_secs: Maximum time to wait in seconds. Defaults to 30.0.

        Raises:
            SandboxError: If the sandbox is destroyed or the timeout expires.
        """
        ...

    def is_ready(self) -> bool:
        """Return whether the sandbox is currently ready to accept commands.

        Returns:
            ``True`` if the sandbox backend is initialized and in a ready state.
        """
        ...

    def list_dir(self, path: str) -> List[DirEntry]:
        """List directory entries inside the sandbox.

        Args:
            path: Absolute path inside the sandbox filesystem.

        Returns:
            A list of ``DirEntry`` objects.

        Raises:
            SandboxError: If the directory cannot be read.
        """
        ...

    def file_exists(self, path: str) -> bool:
        """Check if a file exists inside the sandbox."""
        ...

    def remove_file(self, path: str) -> None:
        """Remove a file or empty directory inside the sandbox."""
        ...

    def rename(self, from: str, to: str) -> None:
        """Rename or move a file inside the sandbox."""
        ...

    def stat(self, path: str) -> FileStat:
        """Return file metadata inside the sandbox."""
        ...

    def read_file(self, path: str) -> bytes:
        """Read a file from inside the sandbox.

        Args:
            path: Absolute path inside the sandbox filesystem.

        Returns:
            File contents as raw bytes.

        Raises:
            FileNotFoundError: If the file does not exist.
            PermissionError: If access is denied.
        """
        ...

    def write_file(self, path: str, data: Union[str, bytes]) -> None:
        """Write bytes to a file inside the sandbox.

        Args:
            path: Absolute path inside the sandbox filesystem.
            data: Raw bytes to write.

        Raises:
            SandboxError: If the write fails.
        """
        ...

    @classmethod
    def from_snapshot(cls, snapshot: Snapshot) -> "Sandbox":
        """Create a new sandbox by restoring from a snapshot.

        Args:
            snapshot: A previously captured ``Snapshot``.

        Returns:
            A new ``Sandbox`` instance with the restored state.

        Raises:
            SandboxError: If restoration fails.
        """
        ...

    def fork(self) -> "Sandbox":
        """Create an independent sandbox that inherits the current state.

        Uses copy-on-write (CoW) for efficient memory sharing.

        Returns:
            A new ``Sandbox`` instance with a copy of the current state.

        Raises:
            SandboxError: If forking fails.
        """
        ...

    def http_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = ...,
        body: Optional[bytes] = ...,
    ) -> HttpResponse:
        """Perform an HTTPS request through the host-side proxy.

        The request is subject to the domain whitelist configured at sandbox creation.

        Args:
            method: HTTP method (``"GET"``, ``"POST"``, etc.).
            url: Full HTTPS URL.
            headers: Optional request headers.
            body: Optional request body as raw bytes.

        Returns:
            An ``HttpResponse`` with status, headers, and body.

        Raises:
            SandboxHttpError: If the domain is not whitelisted or the request fails.
            ConnectionError: If the connection cannot be established.
        """
        ...

    def close(self) -> None:
        """Explicitly release sandbox resources.

        Calling this method multiple times is safe; subsequent calls are no-ops.

        Raises:
            SandboxError: If sandbox destruction fails.
        """
        ...

    def __enter__(self) -> "Sandbox": ...
    def __exit__(
        self,
        exc_type: Optional[type] = ...,
        exc_val: Optional[BaseException] = ...,
        exc_tb: Optional[object] = ...,
    ) -> bool: ...


# --- Exceptions ---


class SandboxError(Exception):
    """Base exception for all mimobox sandbox errors.

    All sandbox-related exceptions inherit from this class. Catch this to handle
    any sandbox error uniformly. Specific subclasses provide finer-grained handling:

    - SandboxProcessError: command exits non-zero or is killed
    - SandboxHttpError: HTTP proxy request denied or failed
    - SandboxLifecycleError: sandbox create/destroy/restore failures

    Certain error codes also map to standard Python built-in exceptions:

    - TimeoutError: command or HTTP timeout (ErrorCode::CommandTimeout, HttpTimeout)
    - FileNotFoundError: file not found (ErrorCode::FileNotFound, IO NotFound)
    - PermissionError: access denied (ErrorCode::FilePermissionDenied, IO PermissionDenied)
    - ValueError: invalid configuration (ErrorCode::InvalidConfig)
    - NotImplementedError: unsupported platform (ErrorCode::UnsupportedPlatform)
    - ConnectionError: HTTP connection/TLS failure (ErrorCode::HttpConnectFail, HttpTlsFail)
    """
    ...


class SandboxProcessError(SandboxError):
    """Raised when a sandbox command exits non-zero or is forcibly killed.

    Maps from ErrorCode::CommandExit(code) and ErrorCode::CommandKilled.
    """
    ...


class SandboxHttpError(SandboxError):
    """Raised when an HTTP proxy request fails or the target host is denied.

    Maps from ErrorCode::HttpDeniedHost, HttpBodyTooLarge, and HttpInvalidUrl.
    HTTP connection/TLS failures map to the built-in ConnectionError instead.
    """
    ...


class SandboxLifecycleError(SandboxError):
    """Raised for sandbox lifecycle issues.

    Maps from ErrorCode::SandboxNotReady, SandboxDestroyed, and SandboxCreateFailed.
    """
    ...


class SandboxTimeoutError(SandboxError):
    """Raised when a sandbox operation times out.

    Maps from ErrorCode::CommandTimeout and HttpTimeout.
    Inherits from SandboxError for unified catching.
    """
    ...


__all__ = [
    "DirEntry",
    "ExecuteResult",
    "FileStat",
    "FileSystem",
    "HttpResponse",
    "Network",
    "Process",
    "Sandbox",
    "SandboxError",
    "SandboxHttpError",
    "SandboxLifecycleError",
    "SandboxTimeoutError",
    "SandboxProcessError",
    "Snapshot",
    "SnapshotOps",
    "StreamEvent",
    "StreamIterator",
]
