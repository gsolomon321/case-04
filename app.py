from datetime import datetime, timezone
import hashlib
import json

from flask import Flask, request, jsonify
from flask_cors import CORS
from pydantic import BaseModel, Field, EmailStr, ValidationError
from typing import Optional

app = Flask(__name__)
CORS(app, resources={r"/v1/*": {"origins": "*"}})


class SurveySubmission(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    email: EmailStr
    age: int = Field(..., ge=13, le=120)
    consent: bool = True
    rating: int = Field(..., ge=1, le=5)
    comments: Optional[str] = Field(None, max_length=1000)
    source: str = "other"
    user_agent: Optional[str] = None
    submission_id: Optional[str] = None


def append_json_line(record: dict, filename="data/survey.ndjson"):
    """Append a single JSON object as one line to a file."""
    with open(filename, "a") as f:
        f.write(json.dumps(record) + "\n")


@app.route("/ping", methods=["GET"])
def ping():
    """Simple health check endpoint."""
    return jsonify({
        "status": "ok",
        "message": "API is alive",
        "utc_time": datetime.now(timezone.utc).isoformat()
    })


@app.post("/v1/survey")
def submit_survey():
    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "invalid_json", "detail": "Body must be application/json"}), 400

    try:
        submission = SurveySubmission(**payload)
    except ValidationError as ve:
        return jsonify({"error": "validation_error", "detail": ve.errors()}), 422

    # Hash PII fields (email and age)
    email_hash = hashlib.sha256(submission.email.encode()).hexdigest()
    age_hash = hashlib.sha256(str(submission.age).encode()).hexdigest()

    hour_stamp = datatime.now(timezone.utc).strftime("%Y%m%d%H")
    submission_id = submission.submission_id or sha256_hex(email_norm + hour_stamp)

    # Compute submission_id if missing: sha256(email + YYYYMMDDHH)
    if not submission.submission_id:
        now_str = datetime.utcnow().strftime("%Y%m%d%H")
        submission_id = hashlib.sha256((submission.email + now_str).encode()).hexdigest()
    else:
        submission_id = submission.submission_id

    # Build the record to save (never store raw email or age)
    record = submission.dict()
    record["email"] = email_hash
    record["age"] = age_hash
    record["submission_id"] = submission_id

    # Add metadata
    record["received_at"] = datetime.now(timezone.utc).isoformat()
    record["ip"] = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    record["user_agent"] = request.headers.get("User-Agent", submission.user_agent)

    # Save the record to file (append-only)
    append_json_line(record)

    return jsonify({"status": "ok"}), 201


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)