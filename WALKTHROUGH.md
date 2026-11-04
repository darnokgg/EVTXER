# EVTXER walkthrough

Six short silent clips, in the order an operator works: collect the logs from
a host, scan them, upload the results, let the queue do it all by itself,
put the dashboards into Kibana, and hunt. Each clip comes with the steps it
shows, so you can follow along on your own stack.

The clips were recorded on a lab: one Windows Server 2022 target (`WS01`), a
local Elasticsearch + Kibana 9.0.8, and a Security Onion 2.4 for the
Dashboards tab. Every account in them is a demo account.

- [1. Collect the logs from a host](#1-collect-the-logs-from-a-host)
- [2. Scan them with Hayabusa](#2-scan-them-with-hayabusa)
- [3. Upload to Elastic](#3-upload-to-elastic)
- [4. Or let the queue do all of it](#4-or-let-the-queue-do-all-of-it)
- [5. Put the dashboards into Kibana](#5-put-the-dashboards-into-kibana)
- [6. Hunt in Kibana](#6-hunt-in-kibana)

---

## 1. Collect the logs from a host

https://github.com/user-attachments/assets/e10f5304-d0e6-4467-b9d0-8b4176595e4a

**What you need first**

- A Windows host you are authorised to examine, and an account that is an
  administrator on it (a domain account, or a local one such as
  `Administrator`).
- One way in: **SMB** (port 445), **WinRM** (5985), or **WinRM over HTTPS**
  (5986). The clip uses WinRM over HTTPS: the traffic is encrypted, and your
  own PC needs no administrator rights and no TrustedHosts change.
- For WinRM over HTTPS the target needs an HTTPS listener. In a domain with
  certificates, `winrm quickconfig -transport:https` on the target does it.
  On a lab host, a self-signed certificate is enough (as administrator, on
  the target):

  ```powershell
  $cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My
  New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Force
  New-NetFirewallRule -DisplayName 'Windows Remote Management (HTTPS-In)' -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow
  ```

  (On Windows 10/11 run `Enable-PSRemoting -Force` first; Windows Server has
  WinRM on already.)

**Steps (Collect tab)**

1. **Targets** - type the hosts, one per line or comma-separated (IP
   addresses or names), or **Load target file...**.
2. **TEST PORTS** - checks 445, 5985 and 5986 on every target and says which
   are open. Nothing is logged on to yet.
3. **Collection Method** - pick **WinRM over HTTPS**. With a self-signed
   certificate, or a target typed as an IP address, tick **Skip certificate
   check**: the data is still encrypted, but nothing proves the target is the
   machine you meant.
4. **Log Category** - **DFIR** (16 logs incident responders use: Security,
   System, PowerShell, Sysmon, Defender...), **All**, or **Custom**.
5. **Collection Credentials** - leave **Domain** empty for a local account;
   EVTXER then logs on as `<target>\<user>` on each host. The password stays
   dots.
6. **VERIFY ACCESS** - logs on, proves the log folder and `Security.evtx`
   are readable, and copies nothing. "1 of 1 target(s) ready to collect."
7. **COLLECT** - every log is hashed (SHA-256) into a manifest, copied as
   `.partial`, checked, and only then renamed. The host's folder lands in
   `evtx\` and goes straight into the queue (section 4).

The target keeps one network logon (event 4624) per connection, and with
WinRM a temporary copy of the logs in `C:\Windows\Temp` that is deleted
afterwards. Nothing is installed there.

---

## 2. Scan them with Hayabusa

https://github.com/user-attachments/assets/404392d1-29b2-434b-9aa0-43629e5e2944

The **Hayabusa** tab scans `.evtx` files from anywhere - a collected host
folder, a share, a USB disk - without the Collect tab.

1. **EVTX folder** - the folder with the `.evtx` files. **+** adds more
   folders, scanned together.
2. **What to make**:
   - **Detections** - Hayabusa's 5,000+ Sigma-based rules, converted to ECS
     (`ecs.jsonl`).
   - **Detections + raw events** - also every event of the logs, not only
     the ones a rule matched (`raw-ecs.jsonl`).
   - **Raw events only** - skips the rules scan.
3. **SCAN + CONVERT** - Hayabusa runs in UTC; the log pane shows its summary
   and the conversion. When it says "Ready to upload", the files are in
   `output\hayabusa\` and the Upload tab has picked them up.

---

## 3. Upload to Elastic

https://github.com/user-attachments/assets/15a47b1b-d19b-43ba-8aa8-82192faa3cfb

**What you need first**

- An Elasticsearch you can reach on port 9200 (Security Onion or plain
  Elastic 8.7 / 9.x) and an account allowed to write `hayabusa-*`. The clip
  uses the lab's `elastic` superuser; for real work create the least-privilege
  role and user in [kibana/ELASTIC-SETUP.txt](kibana/ELASTIC-SETUP.txt). On
  Security Onion, allow your PC to reach 9200 first
  (`so-firewall --apply includehost elasticsearch_rest <your IP>`).

**Steps**

1. **Settings tab, Mission name** - name the mission once, then **Use on the
   Upload tab**. Detections go to `hayabusa-mission-<name>`, raw events to
   `hayabusa-raw-<name>`: their own indices, never the stack's, so a mission
   can be dropped cleanly later.
2. **Upload tab, Elasticsearch connection** - host, port `9200`, username and
   password (or an API key).
3. **Fetch** - reads the server's certificate fingerprint (SHA-256). Confirm
   it once; it is pinned, and every later connection must see the same
   certificate.
4. **VERIFY CONNECTIVITY** - the **ELK** pill at the top turns green and
   shows the cluster and its health.
5. **UPLOAD TO ELK** - streams the detections, and with **Also send the raw
   events** ticked the raw events beside them. Every document has a fixed id,
   so uploading the same data twice adds nothing ("0 already there (not
   doubled)"), and Elasticsearch is asked afterwards how many it holds.
6. **Find it in Kibana** - the data views, a KQL line for this upload and one
   per host, and the Dev Tools counts, each with a **Copy** button.

---

## 4. Or let the queue do all of it

https://github.com/user-attachments/assets/562b95b9-7e06-4537-8827-7bae5ab2a65f

The queue under the tabs runs every host folder through the whole chain by
itself, one step at a time, while you keep working.

1. **Send** - what each host sends: **Detections**, **Raw events**, or
   **Detections + raw events**. **Upload** and **Archive when done** say how
   far each host goes.
2. **Add folders...** - one folder per host: the collection drop folder, or a
   share someone else filled. Hosts collected on the Collect tab are added
   by themselves.
3. **QUEUE THEM** - each host runs Hayabusa scan > ECS > upload > raw events,
   with a moving bar, the detection count and the time per host.

The queue needs a mission name (Settings tab) and a verified connection
(Upload tab) before it uploads; until then a host waits and says why.

---

## 5. Put the dashboards into Kibana

https://github.com/user-attachments/assets/871f1c30-c955-4190-9066-015854da2436

EVTXER ships thirteen dashboards and ten saved searches. The **Dashboards**
tab imports them into **Security Onion**. For plain Elastic, import
`kibana/hayabusa-kibana-objects.ndjson` (Kibana 9) or the `-8.7` file by hand
in Kibana: see [kibana/IMPORT.txt](kibana/IMPORT.txt).

1. On the **Upload** tab, enter the Security Onion host and an SO
   **administrator** (the web login: it signs in like a browser does).
2. **Dashboards** tab - the objects file is found by itself in the
   `kibana dashboards` folder.
3. **Fetch** - Security Onion's web interface (port 443) has a different
   certificate from Elasticsearch (9200), so it is pinned on its own.
4. **IMPORT DASHBOARDS** - objects are overwritten by id, so running it
   twice leaves one copy, not two. **REMOVE HAYABUSA DASHBOARDS** deletes
   only EVTXER's own objects.

---

## 6. Hunt in Kibana

https://github.com/user-attachments/assets/c76bb364-7bef-4f48-805c-b35621b32055

1. **Menu > Dashboards**, search `Hayabusa` (detections) or `Raw Events`.
2. **Set the time picker** to when the events happened - not when you
   uploaded them. A dashboard remembers its own time range, so check it on
   every one you open.
3. **Hayabusa - EVTX Detection Overview** - totals, critical + high, hosts,
   rules fired, levels over time, top rules, hosts, users and channels.
4. **Mission timeline** - detections and raw events of the mission on one
   timeline, per host.
5. **Discover**, data view **Raw Windows events (EVTXER)** - every raw event,
   searchable field by field. For example `host.name:"WS01" and
   event.code:4624` (network and interactive logons on one host). Each event
   carries the ECS fields plus every original field under
   `winlog.event_data.*`.

Detections are in data view **Hayabusa EVTX detections**; **Mission -
everything** holds both, so a detection's surrounding raw events are one
click away (open a detection, then **View surrounding documents**).
