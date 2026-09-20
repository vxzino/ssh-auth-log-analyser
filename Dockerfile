# A container image for running the analyser without installing Python.
#
# Build:
#   docker build -t ssh-auth-log-analyser .
#
# Run against a log file on the host (read-only mount):
#   docker run --rm -v "$(pwd)/samples:/logs:ro" ssh-auth-log-analyser /logs/auth_bruteforce.log
#
# -slim is used rather than the full image because the tool needs only the
# Python standard library, so there is nothing extra to install.
FROM python:3.12-slim

WORKDIR /app

# Only the application code and samples are copied. There is no
# "pip install" step because the tool has no runtime dependencies.
COPY ssh_analyser/ ./ssh_analyser/
COPY samples/ ./samples/

# Run as an unprivileged user. A log analyser never needs root, and giving
# it root would mean a bug in the parser runs as root inside the container.
RUN useradd --create-home analyst
USER analyst

ENTRYPOINT ["python", "-m", "ssh_analyser"]
CMD ["--help"]
