"""Flask web application for Privatiser."""

from __future__ import annotations

import json

from flask import Flask, jsonify, render_template, request

from privatiser import Privatiser


def create_app() -> Flask:
    app = Flask(__name__)

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.post("/api/anonymize")
    def api_anonymize():
        data = request.get_json()
        text = data.get("text", "")
        if not text:
            return jsonify({"error": "No text provided"}), 400

        p = Privatiser()
        result, mapping = p.anonymize(text)
        return jsonify({
            "result": result,
            "mapping": mapping,
            "count": len(mapping),
        })

    @app.post("/api/deanonymize")
    def api_deanonymize():
        data = request.get_json()
        text = data.get("text", "")
        mapping_str = data.get("mapping", "{}")

        if not text:
            return jsonify({"error": "No text provided"}), 400

        try:
            mapping = json.loads(mapping_str) if isinstance(mapping_str, str) else mapping_str
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid mapping JSON"}), 400

        p = Privatiser()
        result = p.deanonymize(text, mapping)
        return jsonify({"result": result})

    return app
