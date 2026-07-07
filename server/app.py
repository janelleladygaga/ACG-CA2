from pathlib import Path

from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "uploads"
WEB_DIR = BASE_DIR / "web"

app = Flask(__name__)


@app.route("/")
def index():
    return send_from_directory(WEB_DIR / "html", "index.html")


@app.route("/js/<path:filename>")
def serve_js(filename):
    return send_from_directory(WEB_DIR / "js", filename)


@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "no file part in request"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "no file selected"}), 400

    filename = secure_filename(file.filename)
    file.save(UPLOAD_DIR / filename)

    return jsonify({"message": f"'{filename}' uploaded successfully"}), 201


@app.route("/files", methods=["GET"])
def list_files():
    filenames = [
        f.name for f in UPLOAD_DIR.iterdir() if f.is_file() and not f.name.startswith(".")
    ]
    return jsonify({"files": filenames})


@app.route("/download/<filename>", methods=["GET"])
def download_file(filename):
    safe_name = secure_filename(filename)
    return send_from_directory(UPLOAD_DIR, safe_name, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
