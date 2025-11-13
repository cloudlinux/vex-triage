FROM python:3.11-slim

LABEL maintainer="TuxCare <support@tuxcare.com>"
LABEL description="Automatically dismiss Dependabot security alerts based on TuxCare VEX data"

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/

# Set Python to run in unbuffered mode (better for logs)
ENV PYTHONUNBUFFERED=1

# Run the action
ENTRYPOINT ["python", "-m", "src.main"]

