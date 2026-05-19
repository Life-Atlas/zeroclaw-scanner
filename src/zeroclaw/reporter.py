"""Report generation: terminal, JSON, PDF."""
from zeroclaw.models import ScanResult, StreamScore


def generate_terminal_report(result: ScanResult) -> str:
    """Rich terminal output of scan results."""
    raise NotImplementedError("Phase 4 task: Varshit implements this")


def generate_json_report(result: ScanResult) -> dict:
    """JSON report for dashboard consumption."""
    raise NotImplementedError("Phase 4 task: Varshit implements this")


def calculate_stream_score(result: ScanResult) -> StreamScore:
    """Calculate 0-10 security score for a stream."""
    raise NotImplementedError("Phase 4 task: Sania implements this")
