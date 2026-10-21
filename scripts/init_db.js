const fs = require('fs');
const path = require('path');

const dbDir = path.join(__dirname, '../db');
const dbFile = path.join(dbDir, 'conformance.db');
const schemaFile = path.join(dbDir, 'schema.sql');

if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

// Touch SQLite database file if it does not exist
if (!fs.existsSync(dbFile)) {
  fs.writeFileSync(dbFile, '', 'utf8');
  console.log(`[DB INIT] Initialized SQLite database file: ${dbFile}`);
} else {
  console.log(`[DB INIT] SQLite database already exists: ${dbFile}`);
}
