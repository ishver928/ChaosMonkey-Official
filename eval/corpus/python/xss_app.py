from flask import Flask, Markup, Response, render_template, render_template_string, request
from markupsafe import escape

app = Flask(__name__)


@app.get("/hello")
def hello():
    name = request.args.get("name", "")
    return f"<h1>Hello {name}</h1>"  # expect: CM-A008


@app.get("/search")
def search():
    return "<p>Results for " + request.args["q"] + "</p>"  # expect: CM-A008


@app.get("/tpl")
def tpl():
    return render_template_string("<p>" + request.args.get("msg", "") + "</p>")  # expect: CM-A008


@app.get("/bio")
def bio():
    return Markup(request.form["bio"])  # expect: CM-A008


@app.get("/hello-safe")
def hello_safe():
    name = request.args.get("name", "")
    return f"<h1>Hello {escape(name)}</h1>"


@app.get("/page")
def page():
    return render_template("page.html", name=request.args.get("name"))


@app.get("/count")
def count():
    n = request.args.get("n", "0")
    return f"<p>{int(n)} items</p>"


@app.get("/plain")
def plain():
    item_id = 42
    return f"<p>Item {item_id}</p>"


@app.get("/results")
def results():
    q = request.args.get("q", "")
    html = "<h1>Results for " + q + "</h1>"
    html += "<p>done</p>"
    return Response(html, mimetype="text/html")  # expect: CM-A008


@app.get("/results-safe")
def results_safe():
    q = escape(request.args.get("q", ""))
    html = "<h1>Results for " + q + "</h1>"
    return Response(html, mimetype="text/html")
