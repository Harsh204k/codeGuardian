# Multi-stage build for CodeGuardian
FROM python:3.11-slim as base

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt pyproject.toml ./

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install -r requirements.txt && \
    pip install -e .

# Copy application code
COPY src/ ./src/
COPY rules/ ./rules/
COPY scripts/ ./scripts/
COPY pytest.ini ./

# Create necessary directories
RUN mkdir -p /app/results /app/models /app/logs

# Create non-root user
RUN groupadd -r codeguardian && \
    useradd -r -g codeguardian -d /app -s /bin/bash codeguardian && \
    chown -R codeguardian:codeguardian /app

# Switch to non-root user
USER codeguardian

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Default command
CMD ["python", "src/cli/cli.py", "--help"]

# Production stage
FROM base as production

# Copy only necessary files for production
COPY --from=base /app /app

# Set production environment
ENV FLASK_ENV=production \
    DJANGO_SETTINGS_MODULE=settings.production

# Expose port
EXPOSE 8000

# Run application
CMD ["python", "-m", "gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "src.web.wsgi:application"]

# Development stage
FROM base as development

# Install development dependencies
RUN pip install pytest ruff black mypy types-PyYAML types-requests

# Copy development files
COPY tests/ ./tests/
COPY demos/ ./demos/

# Set development environment
ENV FLASK_ENV=development \
    FLASK_DEBUG=1

# Default command for development
CMD ["python", "src/cli/cli.py"]
