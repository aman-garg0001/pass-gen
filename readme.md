# PasswordService

A simple password management and generation service.

## Features
- Password generation
- Secure storage of passwords
- RESTful API server
- Docker support for easy deployment

## Project Structure
- `server.js`: Main server file
- `crypto-utils.js`: Cryptographic utilities
- `store.js`: Data storage logic (SQLite, encryption)
- `public/`: Static frontend files (HTML, JS, manifest, service worker)
- `data/`: Data directory (database, etc.)
- `Dockerfile`: Containerization setup

## Getting Started

### Prerequisites
- Node.js (v14 or higher recommended)
- npm
- Docker (optional, for containerized deployment)

### Installation
1. Clone the repository:
   ```sh
   git clone <repo-url>
   cd PasswordService
   ```
2. Install dependencies:
   ```sh
   npm install
   ```

### Running the Server
```sh
node server.js
```

The server will start on the default port (check `server.js` for configuration).

### Using Docker
Build and run the container:
```sh
docker build -t password-service .
docker run -p 3000:3000 password-service
```

## Data Storage: SQLite

This project uses an embedded SQLite database (`passgen.db` by default) for storing password metadata and history. The database is managed using the [`better-sqlite3`](https://github.com/WiseLibs/better-sqlite3) Node.js package.

### Database Schema

- **keys**: Stores password preferences for each app key (length, symbols, category, version, timestamps)
- **history**: Tracks changes and actions (creation, rotation, regeneration) for each key
- **encryption_check**: Used to verify the master password and ensure encryption integrity

### Encryption

All sensitive fields (such as categories) are encrypted at rest using a master password. The master password is required to access or modify stored data. An encrypted marker is stored in the `encryption_check` table to verify the correctness of the master password.

### Database Location

By default, the database file is `passgen.db` in the project root. You can override the location by setting the `DB_PATH` environment variable.

### Example: Changing Database Location

```sh
export DB_PATH=/path/to/your/custom.db
node server.js
```

### Notes
- The database uses Write-Ahead Logging (WAL) mode for better concurrency and reliability.
- All changes to keys are tracked in the `history` table for auditability.

## License
MIT License
