# src/borg/helpers/coverage_diy.py

coverage = {}

def register(branch_id: str) -> None:
    """Register a branch ID as existing (so missing branches can be reported)."""
    coverage.setdefault(branch_id, False)

def mark(branch_id: str) -> None:
    """Mark a branch as taken."""
    coverage[branch_id] = True

def report() -> None:
    print("\n=== DIY COVERAGE REPORT ===")
    taken = [k for k, v in coverage.items() if v]
    missing = [k for k, v in coverage.items() if not v]

    for k in sorted(taken):
        print(f"Branch {k}: taken")

    if missing:
        print("\n--- Missing branches ---")
        for k in sorted(missing):
            print(f"Branch {k}: NOT taken")
