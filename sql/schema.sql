-- SPO SNEAK PEEK OSINT v2.0 — Database Schema (SQLite / ANSI SQL Compatible)
-- Lead Architect & Maintainer: Erik Tonon (@eriktonon | https://eriktonon.com)
-- Security Engine: PE-AGENTS-IBM Security & Strix Shift-Left Hardening

CREATE TABLE IF NOT EXISTS user_spo (
    id_user INTEGER PRIMARY KEY AUTOINCREMENT,
    login VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(300) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS key_api (
    id_key INTEGER PRIMARY KEY AUTOINCREMENT,
    id_user INTEGER NOT NULL,
    user_key VARCHAR(300),
    key_value VARCHAR(600) NOT NULL,
    name_key VARCHAR(100) NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_user) REFERENCES user_spo (id_user) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS project (
    id_project INTEGER PRIMARY KEY AUTOINCREMENT,
    id_user INTEGER NOT NULL,
    name_project VARCHAR(150) NOT NULL,
    scope_project VARCHAR(600) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_user) REFERENCES user_spo (id_user) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scan_history (
    id_scan INTEGER PRIMARY KEY AUTOINCREMENT,
    id_project INTEGER,
    id_user INTEGER NOT NULL,
    scan_type VARCHAR(60) NOT NULL,
    target VARCHAR(255) NOT NULL,
    summary VARCHAR(500),
    payload_json TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_project) REFERENCES project (id_project) ON DELETE SET NULL,
    FOREIGN KEY (id_user) REFERENCES user_spo (id_user) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS personal_trace (
    id_person INTEGER PRIMARY KEY AUTOINCREMENT,
    id_project INTEGER NOT NULL,
    name_person VARCHAR(150),
    date_of_birth DATE,
    email VARCHAR(150),
    telephone VARCHAR(100),
    CPF VARCHAR(100),
    renavam VARCHAR(100),
    RG VARCHAR(200),
    address VARCHAR(1000),
    facebook VARCHAR(500),
    instagram VARCHAR(500),
    twitter VARCHAR(500),
    domain VARCHAR(150),
    business TEXT,
    vehicle TEXT,
    vehicle_plate VARCHAR(50),
    proceedings TEXT,
    FOREIGN KEY (id_project) REFERENCES project (id_project) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS servers (
    id_server INTEGER PRIMARY KEY AUTOINCREMENT,
    id_project INTEGER NOT NULL,
    address VARCHAR(150),
    ports_open VARCHAR(1000),
    ports_filtred VARCHAR(1000),
    describe TEXT,
    ip_address VARCHAR(100),
    FOREIGN KEY (id_project) REFERENCES project (id_project) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS domain (
    id_domain INTEGER PRIMARY KEY AUTOINCREMENT,
    id_project INTEGER NOT NULL,
    owner_name VARCHAR(200),
    owner_document VARCHAR(100),
    owner_email VARCHAR(150),
    domain VARCHAR(150),
    data_creation VARCHAR(100),
    data_expiration VARCHAR(100),
    host_address VARCHAR(150),
    FOREIGN KEY (id_project) REFERENCES project (id_project) ON DELETE CASCADE
);
