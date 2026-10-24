import ast
import os

from flask import request


def vuln_eval(expr):
    return eval(expr)  # expect: CM-A003


def vuln_exec():
    exec(request.form["code"])  # expect: CM-A003


def safe_literal(expr):
    return ast.literal_eval(expr)


def safe_eval_constant():
    return eval("1 + 1")


def vuln_open():
    with open("/srv/files/" + request.args["filename"]) as fh:  # expect: CM-A007
        return fh.read()


def safe_open_config(config_path):
    # fp-fixed: a parameter named "path" is not user input on its own
    with open(config_path) as fh:
        return fh.read()


def safe_open_basename():
    from werkzeug.utils import secure_filename
    with open("/srv/files/" + secure_filename(request.args["filename"])) as fh:
        return fh.read()


def vuln_open_joined():
    name = request.args.get("name", "readme.txt")
    path = os.path.join("/srv/files", name)
    with open(path) as fh:  # expect: CM-A007
        return fh.read()


def safe_open_contained():
    name = request.args.get("name", "readme.txt")
    base = os.path.realpath("/srv/files")
    path = os.path.realpath(os.path.join(base, name))
    if not path.startswith(base + os.sep):
        raise ValueError("invalid path")
    with open(path) as fh:
        return fh.read()
