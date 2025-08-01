# Use official Python image as base
FROM python:3.10-slim

# Set working directory in container
WORKDIR /app

# Copy current directory contents into container
COPY . .

# Run the Python app
CMD ["python", "app.py"]
