FROM python:3.11-slim

LABEL maintainer="TuxCare <support@tuxcare.com>"
LABEL description="Automatically dismiss Dependabot security alerts based on TuxCare VEX data"

# Set working directory
WORKDIR /action

# Install uv for faster dependency installation
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy project files
COPY pyproject.toml .
COPY README.md .
COPY src/ ./src/

# Install dependencies using uv (much faster than pip)
RUN uv pip install --system --no-cache .

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set Python to run in unbuffered mode (better for logs)
ENV PYTHONUNBUFFERED=1

# Add the action directory to Python path
ENV PYTHONPATH=/action

# Run the action via entrypoint script
ENTRYPOINT ["/entrypoint.sh"]

