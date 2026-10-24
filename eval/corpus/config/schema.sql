CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  email TEXT NOT NULL,
  password VARCHAR(255), -- expect: CM-D003
  ssn VARCHAR(11), -- expect: CM-P008
  dob DATE, -- expect: CM-P008
  ssn_encrypted BLOB
);
