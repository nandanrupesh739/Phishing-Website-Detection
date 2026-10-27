# Contributing to PhishGuard AI

Thank you for your interest in contributing to PhishGuard AI! We welcome bug reports, documentation updates, code improvements, and new test cases.

Please follow these guidelines to ensure a smooth contribution process.

---

## Development Setup

### Prerequisites
- **Python**: 3.11 or 3.12 (Python 3.14 compatible)
- **Node.js**: 20+ and npm 10+
- **Git**

### 1. Clone the Repository
```bash
git clone https://github.com/nandanrupesh739/Phishing-Website-Detection.git
cd Phishing-Website-Detection
```

### 2. Backend Environment Setup
```bash
# Create and activate virtual environment
python -m venv .venv

# On Linux/macOS:
source .venv/bin/activate

# On Windows (PowerShell):
.venv\Scripts\Activate.ps1

# Install core and development dependencies
pip install -r requirements.txt -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install
```

### 3. Frontend Environment Setup
```bash
cd frontend
npm install
cd ..
```

---

## Running Quality Checks & Tests

Before submitting a pull request, verify that all linters, type checks, and tests pass with zero warnings:

### Backend Checks
```bash
# Linting and formatting
ruff check .
ruff format --check .

# Static type checking (strict backend coverage)
mypy backend

# Pytest test suite with code coverage (target: >= 85% on backend/)
pytest backend/tests/ -v --cov=backend

# End-to-end smoke test (starts Flask on ephemeral port, tests all endpoints, clean shutdown)
python scripts/e2e_smoke.py
```

### Frontend Checks
```bash
cd frontend

# ESLint check
npm run lint

# Vitest component and unit test suite
npm test

# Production build check
npm run build

cd ..
```

---

## Commit Message Conventions

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <short imperative description>
```

### Allowed Types:
- `feat`: A new user-facing feature or API capability
- `fix`: A bug fix
- `docs`: Documentation updates or additions
- `test`: Adding or refactoring tests
- `refactor`: Code restructure that neither fixes a bug nor adds a feature
- `perf`: Code optimization for speed or memory
- `chore`: Tooling, build config, dependency bumps, or repository maintenance

### Examples:
- `feat(api): add batch prediction endpoint with explanation support`
- `fix(features): handle punycode and edge case ports without crashing`
- `test(backend): add coverage for database migration and rate limiting`
- `docs(readme): update calibration and ROC evaluation figures`

---

## Pull Request Checklist

When submitting a PR, verify:
- [ ] Pytest passes with >= 85% coverage on `backend/`.
- [ ] `mypy backend` reports 0 issues.
- [ ] `ruff check .` reports 0 issues.
- [ ] Frontend `npm run lint`, `npm test`, and `npm run build` pass with 0 errors.
- [ ] `python scripts/e2e_smoke.py` exits successfully.
- [ ] No dataset files (`data/*.csv`), model binaries (`*.joblib`, `*.pkl`), databases (`*.db`), or `.env` files are tracked in git.
- [ ] URLs submitted for scanning are never visited over the network; they remain inert text strings only.
