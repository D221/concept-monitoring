# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file and install dependencies
COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application's code
COPY server/ ./server/

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Set python path to find server module
ENV PYTHONPATH=/app

# Run app.py when the container launches with Gunicorn
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "server.app:app"]
