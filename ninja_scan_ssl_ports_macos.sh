#!/usr/bin/env bash
#
# NinjaOne: Local SSL & Port Enumerator (macOS)
#
# - Uses lsof to list listening TCP ports
# - Uses openssl s_client to fetch certificates and test TLS protocol negotiation
# - Writes results to NinjaOne CLI: /Applications/NinjaRMMAgent/programdata/ninjarmm-cli set <field> "<value>"
#
# Header, logging and simple test helper included.
#

set -euo pipefail
SCRIPT_NAME="$(basename "$0")"
LOGFILE="/tmp/${SCRIPT_NAME%.*}.log"
exec 3>&1 1>>"$LOGFILE" 2>&1

FieldCert="sslCertInfo"
FieldCiphers="sslCipherSuites"
FieldPorts="openPortsInfo"
NINJA_CLI="/Applications/NinjaRMMAgent/programdata/ninjarmm-cli"
HANDSHAKE_TIMEOUT=5   # per OpenSSL call we won't block longish - still can hang depending on socket behavior
MAX_PORTS=50

log() {
  echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ")	$*" >&3
  echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ")	$*" >>"$LOGFILE"
}

log "Starting run"

# 1) discover listening TCP ports
log "Enumerating listening TCP ports with lsof..."
ports=()
while IFS= read -r line; do
  # parse lsof output line format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
  # We'll use lsof -nP -iTCP -sTCP:LISTEN -F to get machine-parsable output if available
  true
done < <(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null || true)

# Better parse using lsof -F
mapfile -t lsof_lines < <(lsof -nP -iTCP -sTCP:LISTEN -F pn 2>/dev/null || true)
# Fields come as p<pid> n<NAME> pairs, e.g. p1234 n*:80
declare -A tmp
current_pid=""
for entry in "${lsof_lines[@]}"; do
  prefix="${entry:0:1}"
  val="${entry:1}"
  if [[ "$prefix" == "p" ]]; then
    current_pid="$val"
  elif [[ "$prefix" == "n" && -n "$current_pid" ]]; then
    # extract port from NAME which can be like *:80 or 127.0.0.1:631
    port="${val##*:}"
    ports+=("$port:$current_pid")
  fi
done

# Deduplicate ports and limit
declare -A seen
clean_ports=()
for pp in "${ports[@]}"; do
  p="${pp%%:*}"
  pid="${pp##*:}"
  if [[ -z "${seen[$p]:-}" ]]; then
    seen[$p]=1
    clean_ports+=("$p:$pid")
  fi
done

if (( ${#clean_ports[@]} == 0 )); then
  log "No listening TCP ports found via lsof."
fi

# Limit to MAX_PORTS
if (( ${#clean_ports[@]} > MAX_PORTS )); then
  log "Found ${#clean_ports[@]} ports, limiting to first $MAX_PORTS for runtime control."
  clean_ports=("${clean_ports[@]:0:$MAX_PORTS}")
fi

# Build open ports output
ports_output="Open TCP Listening Ports:\n"
for entry in "${clean_ports[@]}"; do
  port="${entry%%:*}"
  pid="${entry##*:}"
  procname="$(ps -p "$pid" -o comm= 2>/dev/null || echo "PID:$pid")"
  ports_output+="Port ${port} - Process: ${procname} (PID ${pid})\n"
done

log "Ports discovered: ${#clean_ports[@]}"

# 2) SSL certs & 3) cipher/protocol checks using openssl
certs_output=""
ciphers_output=""
# Protocol flags to try (OpenSSL supports -tls1_3 -tls1_2 -tls1_1 -tls1)
proto_flags=("-tls1_3" "-tls1_2" "-tls1_1" "-tls1")
# Keep a short list of common modern ciphers if you want to test individually (optional)
# However, we'll attempt handshake and parse negotiated cipher via s_client instead of iterating ciphers to save time.

for entry in "${clean_ports[@]}"; do
  port="${entry%%:*}"
  log "Testing port $port for TLS/SSL..."
  # Try a simple s_client handshake (try tls1_3 then tls1_2 etc)
  port_has_cert=0
  for pf in "${proto_flags[@]}"; do
    # if openssl doesn't support -tls1_3, it will error; allow failure
    # suppress interactive hangs by sending EOF
    out=$( (echo | openssl s_client -connect "127.0.0.1:${port}" -servername "localhost" ${pf} 2>/dev/null) || true )
    # Check if certificate block present
    if echo "$out" | grep -q "-----BEGIN CERTIFICATE-----"; then
      port_has_cert=1
      # Extract cert summary
      cert_summary=$(echo "$out" | awk '/-----BEGIN CERTIFICATE-----/{f=1} f && /-----END CERTIFICATE-----/{print; f=0} f{print}' | \
        openssl x509 -noout -subject -issuer -dates -fingerprint 2>/dev/null || true)
      if [[ -z "$cert_summary" ]]; then
        # fallback: get subject/issuer/dates using s_client piped to x509
        cert_summary=$(echo "$out" | openssl x509 -noout -subject -issuer -dates -fingerprint 2>/dev/null || true)
      fi
      certs_output+="Port ${port} (via ${pf}):\n${cert_summary}\n\n"
      # Try to find negotiated cipher line, common s_client outputs "Cipher    : <name>" or "Cipher is <name>"
      negotiated=$(echo "$out" | sed -n -e 's/^ *Cipher *: *//Ip' -e 's/^ *Cipher is *//Ip' -n | head -n1 || true)
      if [[ -z "$negotiated" ]]; then
        negotiated=$(echo "$out" | grep -i "Cipher is" -m1 || true)
      fi
      if [[ -n "$negotiated" ]]; then
        ciphers_output+="Port ${port} - Proto ${pf} - Negotiated: ${negotiated}\n"
      else
        # fallback: examine SSL-Session header
        sslsession=$(echo "$out" | sed -n '/SSL-Session:/,/^[[:space:]]*$/p' | sed -n 's/^ *Cipher *: *//Ip' | head -n1 || true)
        if [[ -n "$sslsession" ]]; then
          ciphers_output+="Port ${port} - Proto ${pf} - Negotiated: ${sslsession}\n"
        else
          ciphers_output+="Port ${port} - Proto ${pf} - Negotiated: (unknown)\n"
        fi
      fi
      # we found a cert for this proto; break to avoid repeated captures for same port
      break
    fi
  done
  if (( port_has_cert == 0 )); then
    certs_output+="Port ${port}: No TLS certificate / handshake with tested protocol flags.\n\n"
  fi
done

# If no ciphers captured, indicate that.
if [[ -z "$ciphers_output" ]]; then
  ciphers_output="No TLS protocol/cipher negotiation info discovered on tested ports."
fi

# 4) push results to NinjaOne fields via CLI
if [[ ! -x "$NINJA_CLI" ]]; then
  log "Ninja CLI not found at $NINJA_CLI - cannot set fields. Exiting."
  echo -e "$ports_output" >&3
  exit 2
fi

# helper: set field (escape newlines)
set_field() {
  local field="$1"
  local value="$2"
  # Use heredoc to pass large content safely to CLI if CLI supports stdin; if not, fallback to quoted param
  # The Ninja CLI accepts arguments; use printf to produce a single-line slug if needed.
  # We will pass with quotes - be mindful of CLI parsing.
  "$NINJA_CLI" set "$field" "$value" || { log "Failed to set $field"; }
  log "Set field $field"
}

log "Pushing open ports field..."
set_field "$FieldPorts" "$(printf "%b" "$ports_output")"

log "Pushing cert info field..."
set_field "$FieldCert" "$(printf "%b" "$certs_output")"

log "Pushing cipher info field..."
set_field "$FieldCiphers" "$(printf "%b" "$ciphers_output")"

log "Completed. Log at $LOGFILE"
echo "Completed. See $LOGFILE for details."
