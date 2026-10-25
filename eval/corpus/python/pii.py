import logging

logger = logging.getLogger(__name__)

SUPPORT_CONTACT = "maya.okafor@example.com"  # expect: CM-P001
FIXTURE_PHONE = "(415) 555-0134"  # expect: CM-P002
FIXTURE_SSN = "219-09-9999"  # expect: CM-P003
FIXTURE_CARD = "4111 1111 1111 1111"  # expect: CM-P004
fixture = {"dob": "1990-04-12"}  # expect: CM-P005


def signup(user):
    logger.info("new signup %s", user)  # expect: CM-P006
    print(f"email={user['email']} dob={user['dob']}")  # expect: CM-P006


def save(cur, name, dob, ssn):
    cur.execute("INSERT INTO people (full_name, dob, ssn) VALUES (?, ?, ?)", (name, dob, ssn))  # expect: CM-P008


def save_encrypted(cur, name, dob_token):
    cur.execute("INSERT INTO people (full_name, dob_encrypted) VALUES (?, ?)", (name, dob_token))


def log_safe(uid):
    logger.info("signup id=%s", uid)


class Patient(Base):
    ssn = Column(String(11))  # expect: CM-P008
    date_of_birth = Column(Date)  # expect: CM-P008
    ssn_hash = Column(String(64))
