-- Таблица конфигураций сканирования
CREATE TABLE scan_configs (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    target_type VARCHAR(20) NOT NULL, -- 'image', 'filesystem'
    target_pattern TEXT NOT NULL,      -- паттерн образа
    scanners TEXT[] NOT NULL DEFAULT '{vuln,secret}',
    image_config_scanners TEXT[] DEFAULT '{}',
    severity TEXT[] NOT NULL DEFAULT '{UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL}',
    ignore_unfixed BOOLEAN NOT NULL DEFAULT FALSE,
    detection_priority VARCHAR(20) NOT NULL DEFAULT 'precise',
    pkg_types TEXT[] DEFAULT '{os,library}',
    pkg_relationships TEXT[] DEFAULT '{root,direct,indirect,unknown}',
    registry_auth JSONB,
    ignore_file TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Таблица заданий
CREATE TABLE scan_jobs (
    id SERIAL PRIMARY KEY,
    config_id INTEGER REFERENCES scan_configs(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    status VARCHAR(20) NOT NULL,
    target TEXT NOT NULL,
    parameters JSONB NOT NULL,
    pid INTEGER,
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    error TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Таблица результатов
CREATE TABLE scan_results (
    id SERIAL PRIMARY KEY,
    job_id INTEGER NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    result_type VARCHAR(20) NOT NULL,
    target TEXT,
    class VARCHAR(50),
    data JSONB NOT NULL
);

CREATE INDEX idx_scan_jobs_config_id ON scan_jobs(config_id);
CREATE INDEX idx_scan_results_job_id ON scan_results(job_id);

-- Таблица групп
CREATE TABLE scan_groups (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    config_ids INTEGER[] NOT NULL DEFAULT '{}',
    schedule TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Таблица записей выполнения по расписанию
CREATE TABLE schedule_records (
    id SERIAL PRIMARY KEY,
    group_id INTEGER NOT NULL REFERENCES scan_groups(id) ON DELETE CASCADE,
    job_ids INTEGER[] NOT NULL DEFAULT '{}',
    scheduled_at TIMESTAMP NOT NULL,
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    status VARCHAR(20) NOT NULL
);