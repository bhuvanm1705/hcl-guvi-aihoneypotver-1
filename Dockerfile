FROM python:3.11-slim

WORKDIR /app

# Copy requirements first to leverage cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Expose the port (Railway sets PORT env var, but good practice to expose generic)
EXPOSE 5000

# Run the application directly
CMD ["python", "app.py"]
