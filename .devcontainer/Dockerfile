FROM python:3

COPY requirements_dev.txt /tmp/pip-tmp/
RUN pip --no-cache-dir install -r /tmp/pip-tmp/requirements_dev.txt && rm -rf /tmp/pip-tmp
