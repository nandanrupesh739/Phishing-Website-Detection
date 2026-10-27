.PHONY: help setup data train test run-backend run-frontend lint format clean

help:
	@echo "PhishGuard AI — Automation Commands"
	@echo "  make setup        Install backend and frontend dependencies"
	@echo "  make data         Download dataset via download_data.py"
	@echo "  make train        Execute complete training pipeline and export assets"
	@echo "  make test         Execute backend pytest, frontend vitest, and e2e smoke"
	@echo "  make run-backend  Start Flask backend server on port 5000"
	@echo "  make run-frontend Start Vite frontend dev server on port 5173"
	@echo "  make lint         Run ruff, mypy, and frontend eslint"
	@echo "  make format       Format code with ruff"
	@echo "  make clean        Remove cache and coverage directories"

setup:
	python -m pip install --upgrade pip
	pip install -r requirements.txt -r requirements-dev.txt
	cd frontend && npm install

data:
	python download_data.py

train:
	python train.py
	python scripts/export_docs_assets.py

test:
	pytest backend/tests/ -v --cov=backend
	cd frontend && npm test -- --run
	python scripts/e2e_smoke.py

run-backend:
	python -m backend.app

run-frontend:
	cd frontend && npm run dev

lint:
	ruff check .
	mypy backend
	cd frontend && npm run lint

format:
	ruff format .

clean:
	python -c "import shutil, pathlib; [shutil.rmtree(p, ignore_errors=True) for p in pathlib.Path('.').rglob('__pycache__')]"
	python -c "import shutil, pathlib; [shutil.rmtree(p, ignore_errors=True) for p in [pathlib.Path('.pytest_cache'), pathlib.Path('.mypy_cache'), pathlib.Path('.ruff_cache'), pathlib.Path('htmlcov')]]"
