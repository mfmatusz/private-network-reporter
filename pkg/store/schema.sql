-- endpoints: discovered hosts catalog (from ARP / events)
CREATE TABLE IF NOT EXISTS endpoints (
  ip           TEXT PRIMARY KEY,
  mac          TEXT,
  hostname     TEXT,
  type         TEXT,                -- phone|pc|iot|unknown
  first_seen   TIMESTAMP NOT NULL,
  last_seen    TIMESTAMP NOT NULL,
  last_scan_at TIMESTAMP,        
  up           INTEGER NOT NULL DEFAULT 1  -- 1=active, 0=inactive
);

-- scans: scans metadata
CREATE TABLE IF NOT EXISTS scans (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  ip           TEXT NOT NULL,
  started_at   TIMESTAMP NOT NULL,
  finished_at  TIMESTAMP NOT NULL,
  scan_type    TEXT NOT NULL,
  result_json  TEXT
);

-- ports: ports results
CREATE TABLE IF NOT EXISTS ports (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id  INTEGER NOT NULL,
  ip       TEXT NOT NULL,
  port     INTEGER NOT NULL,
  proto    TEXT NOT NULL,
  state    TEXT,
  service  TEXT,
  product  TEXT,
  version  TEXT,
  FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- indexes
CREATE INDEX IF NOT EXISTS scans_ip_started_idx ON scans(ip, started_at);
CREATE INDEX IF NOT EXISTS ports_ip_port_idx    ON ports(ip, port);
CREATE INDEX IF NOT EXISTS endpoints_ip_idx     ON endpoints(ip);
CREATE INDEX IF NOT EXISTS endpoints_lastscan_idx ON endpoints(last_scan_at);
