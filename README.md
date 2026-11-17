# Cyberlens: database documents (AP project)

Database documents for **Cyberlens**, our AP capstone: a web app (React, Express, PostgreSQL) that scans public
GitHub repositories with Semgrep, Gitleaks and OSV-Scanner and maps the findings to OWASP Top 10 and CWE.

This repository holds only the DBMS documents. The application code is in the team's separate project repository.

## Team

Team T0028, Section B.

| Role | Name | Enrollment No. | GitHub username |
|------|------|----------------|-----------------|
| Group Lead | Aman Mishra | 2501010050 | amanmishra20feb |
| Member 2 | Shivansh Pandey | 2501010698 | pandeyshivansh-tech |
| Member 3 | Abhinav Tayal | 2501010016 | abhinav560 |
| Member 4 | Prashant | 2501010345 | prashantofficial627-hash |

## Contents

| File | What it is |
|------|------------|
| `dbms/01_normalization.md` | The app's data taken through 1NF, 2NF and 3NF, with BCNF checked, and where the running schema deliberately differs |
| `dbms/02_er_diagram.png` | ER diagram of the three real tables (users, scans, findings); source in `dbms/02_er_diagram.mmd` |
| `dbms/03_schema.sql` | `CREATE TABLE` statements and indexes of the running schema, runnable on PostgreSQL |

More files will be added to `dbms/` as the project goes on.
