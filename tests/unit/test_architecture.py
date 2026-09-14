import subprocess

def test_architecture_contracts():
    """Garantiza que no existan acoplamientos prohibidos entre módulos."""
    result = subprocess.run(
        ["lint-imports", "--no-cache"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0, f"Violación de arquitectura detectada:\n{result.stdout}"