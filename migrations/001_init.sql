CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    type VARCHAR(10) NOT NULL,
    target TEXT NOT NULL,
    status VARCHAR(20) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    error TEXT
);

CREATE TABLE vulnerabilities (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    vuln_id TEXT,
    package TEXT,
    installed_version TEXT,
    fixed_version TEXT,
    severity TEXT,
    description TEXT
);

CREATE TABLE packages (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    name TEXT,
    version TEXT,
    arch TEXT
);

CREATE INDEX idx_vulnerabilities_scan_id ON vulnerabilities(scan_id);
CREATE INDEX idx_packages_scan_id ON packages(scan_id);
