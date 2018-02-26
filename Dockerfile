# Use an official Python runtime as a parent image
FROM python:3.6-slim

# set the working directory to /app
WORKDIR /app

# copy the requirements into the container at /app
ADD ./requirements.txt /app/requirements.txt

# Install any needed packages specified in requirements.txt
RUN pip install -r requirements.txt

# Copy the current directory contents into the container at /app
ADD . /app

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Run run.py when the container launches, this is app entry point
CMD python run.py
