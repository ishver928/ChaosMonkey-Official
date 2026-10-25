import os

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # expect: CM-S001
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # expect: CM-S002
GITHUB_TOKEN = "ghp_DEMOfakeTOKENnotREAL0000000000000000"  # expect: CM-S003
STRIPE_KEY = "@@FAKE:stripe@@"  # expect: CM-S004
OPENAI_API_KEY = "sk-proj-DEMOnotREAL1234567890abcdefXYZ"  # expect: CM-S005
ANTHROPIC_API_KEY = "sk-ant-api03-DEMO-not-a-real-key-000000000000"  # expect: CM-S006
MAPS_KEY = "@@FAKE:google@@"  # expect: CM-S007
SLACK_TOKEN = "xoxb-not-a-real-token-this-will-not-work"  # expect: CM-S008
DATABASE_URL = "postgres://app:Sup3rS3cretPw@db.internal:5432/app"  # expect: CM-S011
HEADERS = {"Authorization": "Bearer abcDEF0123456789ghiJKL0123456789"}  # expect: CM-S012
SIGNING_KEY = "q8V2kT9zX4mR7pL1wN6bY3cJ5hF0dG8s"  # expect: CM-S014
DB_PASSWORD = "hunter2-Prod!"  # expect: CM-S014
SECRET_KEY = "flask-dev-key-9f8e7d6c5b4a"  # expect: CM-D004
TEST_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"  # expect: CM-S010
# expect-next: CM-S009
PRIVATE_KEY = """@@FAKE:pem_begin@@
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEXdemoONLYnotREALkeyMATERIAL00
@@FAKE:pem_end@@"""

# Safe lookalikes (fp-fixed cases are marked)
PLACEHOLDER_KEY = "YOUR_API_KEY"
TEMPLATE_AWS = "AKIAXXXXXXXXXXXXXXXX"  # fp-fixed: template key in a known format
FROM_ENV = os.environ.get("OPENAI_API_KEY")
ENV_NAME_TOKEN = "GITHUB_TOKEN"  # fp-fixed: value is an env-var name
TOKEN_ERROR = "token_expired"  # fp-fixed: value is a word identifier
CHANGEME_PASSWORD = "changeme"
EXAMPLE_SECRET = "example-secret-value"
PASSWORD_FIELD = "password-input"  # fp-fixed: form field id, not a password
DATABASE_URL_ENV = "postgres://app:${DB_PASSWORD}@db.internal:5432/app"
OPENAI_PLACEHOLDER = "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
