#!/usr/bin/env python3
"""Validation script to check if all modules can be imported."""

import sys

def validate_imports():
    """Validate that all modules can be imported."""
    print("Validating module imports...")
    
    errors = []
    
    # Try importing each module
    modules = [
        "src.config",
        "src.utils",
        "src.vex_client",
        "src.version_matcher",
        "src.github_client",
        "src.triage",
        "src.main",
    ]
    
    for module in modules:
        try:
            __import__(module)
            print(f"✓ {module}")
        except Exception as e:
            errors.append(f"✗ {module}: {e}")
            print(f"✗ {module}: {e}")
    
    if errors:
        print(f"\n{len(errors)} module(s) failed to import")
        return False
    else:
        print(f"\n✓ All {len(modules)} modules imported successfully!")
        return True


def validate_structure():
    """Validate project structure."""
    import os
    
    print("\nValidating project structure...")
    
    required_files = [
        "action.yml",
        "Dockerfile",
        "requirements.txt",
        "README.md",
        "CHANGELOG.md",
        ".gitignore",
        "src/__init__.py",
        "src/main.py",
        "src/config.py",
        "src/utils.py",
        "src/vex_client.py",
        "src/version_matcher.py",
        "src/github_client.py",
        "src/triage.py",
        "tests/__init__.py",
        "tests/test_version_matcher.py",
        "tests/test_vex_client.py",
        "tests/fixtures/sample_vex.json",
    ]
    
    missing = []
    for file in required_files:
        if os.path.exists(file):
            print(f"✓ {file}")
        else:
            missing.append(file)
            print(f"✗ {file} (missing)")
    
    if missing:
        print(f"\n{len(missing)} file(s) missing")
        return False
    else:
        print(f"\n✓ All {len(required_files)} files present!")
        return True


def main():
    """Main validation."""
    print("=" * 60)
    print("TuxCare VEX Auto-Triage - Validation")
    print("=" * 60)
    
    structure_ok = validate_structure()
    imports_ok = validate_imports()
    
    print("\n" + "=" * 60)
    if structure_ok and imports_ok:
        print("✓ VALIDATION PASSED")
        print("=" * 60)
        return 0
    else:
        print("✗ VALIDATION FAILED")
        print("=" * 60)
        return 1


if __name__ == "__main__":
    sys.exit(main())

