import json
import pickle

import yaml


def vuln_pickle(blob):
    return pickle.loads(blob)  # expect: CM-A004


def vuln_yaml(text):
    return yaml.load(text)  # expect: CM-A004


def vuln_yaml_full(text):
    return yaml.load(text, Loader=yaml.Loader)  # expect: CM-A004


def safe_yaml(text):
    return yaml.safe_load(text)


def safe_yaml_loader(text):
    return yaml.load(text, Loader=yaml.SafeLoader)


def safe_json(raw):
    return json.loads(raw)


def safe_pickle_dumps(obj):
    return pickle.dumps(obj)
