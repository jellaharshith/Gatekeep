# Wazuh lab for field-survival testing

Goal: learn which attacker-written bytes survive ingestion into the alert an AI agent reads.
Use an isolated lab network you own. Never point these tools at production or third-party systems.

## 1. Stand up Wazuh (single node, Docker)

Follow the official `wazuh-docker` single-node instructions for the current 4.x release
(https://github.com/wazuh/wazuh-docker, `single-node/`). In outline:

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b <latest-4.x-tag>
cd wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```

Change the default credentials in the compose file before you start. Note the exact version you used:
your survival table is only valid for that version.

## 2. Accept syslog from your lab subnet

In the manager config (`config/wazuh_cluster/wazuh_manager.conf` in wazuh-docker), add:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>10.0.0.0/8</allowed-ips>   <!-- your lab subnet -->
</remote>
```

Make sure `514/udp` is published by the manager container, then restart it.

Optional: set `<logall_json>yes</logall_json>` and enable the archives index in Filebeat to also see
lines that did not match any rule. Many payloads die exactly there.

## 3. Inject and measure

```bash
gatekeep lab inject --target <manager-ip> --vector ssh.username --family authority_forgery --i-own-this-lab
# prints a marker like SG1A2B3C and the exact payload sent

gatekeep lab survival --indexer https://<manager-ip>:9200 --marker SG1A2B3C \
  --payload "<payload printed above>" --user <user> --password '<pass>' --insecure
```

`survival` lists every field of every matching alert that contains the marker, with `intact: true/false`
and how many characters arrived after the marker.

## 4. Record results

| Vector | Decoder / rule hit | Fields containing payload | Intact? | Chars kept | Notes |
|---|---|---|---|---|---|
| ssh.username | | | | | |
| http.user_agent | | | | | |
| http.uri | | | | | |
| dns.qname | | | | | |
| email.subject | | | | | |

Then update `gatekeep/injection/vectors.py` (`max_len`, `transform`) to match what you measured, and
reference this table in the commit message.
