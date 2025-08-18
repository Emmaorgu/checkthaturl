# fixtures_server.py
from flask import Flask, request, redirect, send_from_directory
app = Flask(__name__, static_folder="fixtures")

@app.route("/<path:path>", methods=["GET","POST"])
def serve(path):
    # simple POST redirect for the form
    if request.method == "POST":
        if path.lower().endswith("timer.html"):
            return redirect("/timer.html", code=302)
    return send_from_directory("fixtures", path)

@app.route("/")
def root():
    return send_from_directory("fixtures", "timer.html")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8008)
