# nsmon — monitorizare multi-server netstreaming.eu

Panou central cu login pe **https://netstreaming.eu/monitor**, cu câte o subpagină pentru fiecare server:

| Pagină | Server |
|---|---|
| `/monitor/` | prezentare generală (toate serverele) |
| `/monitor/main` | netstreaming.eu (principal) |
| `/monitor/s2` | S2: media server nginx, primește de la S3 |
| `/monitor/s3` | S3: encoder |
| `/monitor/s4` | S4: pull de la S2 și alte surse |

Fiecare pagină arată CPU, RAM, discuri, load, trafic, uptime, SSL, fail2ban, vechimea playlisturilor HLS, procesele ffmpeg/astra/srt și serviciile, cu butoane **Restart / Start / Log / Reload nginx** (`nginx -t` rulează înainte de reload).

## Fișiere

| Fișier | Unde rulează |
|---|---|
| `install-main.sh` | netstreaming.eu: panou + agent local |
| `install-s2.sh` | S2: agent |
| `install-s3.sh` | S3: agent |
| `install-s4.sh` | S4: agent |
| `nsmon.sh` | nucleul comun, descărcat automat de scripturile de mai sus |

## Instalare

**1. Pe netstreaming.eu**
```bash
curl -fsSL https://raw.githubusercontent.com/maxvideostar/monitor/main/install-main.sh | sudo bash
```
Cere user și parolă pentru pagina de login. La final afișează token-ul și IP-ul de folosit la pasul 2.

**2. Pe S2, S3 și S4** (fiecare cu scriptul lui)
```bash
curl -fsSL https://raw.githubusercontent.com/maxvideostar/monitor/main/install-s2.sh | sudo bash -s <TOKEN> <IP_NETSTREAMING>
curl -fsSL https://raw.githubusercontent.com/maxvideostar/monitor/main/install-s3.sh | sudo bash -s <TOKEN> <IP_NETSTREAMING>
curl -fsSL https://raw.githubusercontent.com/maxvideostar/monitor/main/install-s4.sh | sudo bash -s <TOKEN> <IP_NETSTREAMING>
```

**3. Înapoi pe netstreaming.eu**
```bash
bash /root/nsmon.sh add s2 <IP_S2>
bash /root/nsmon.sh add s3 <IP_S3>
bash /root/nsmon.sh add s4 <IP_S4>
```
Fiecare comandă testează imediat conexiunea. Subpaginile apar fără restart.

> Dacă repo-ul e privat, `curl` pe raw nu funcționează. În locul lui folosește
> `git clone https://github.com/maxvideostar/monitor && cd monitor && sudo bash install-s2.sh <TOKEN> <IP>`.

## Comenzi utile (netstreaming.eu)

```bash
bash /root/nsmon.sh token          # afișează token-ul pentru agenți
bash /root/nsmon.sh list           # serverele din panou
bash /root/nsmon.sh del s4         # scoate un server
bash /root/nsmon.sh panel          # reinstalare / schimbare parolă (Enter = păstrează userul)
journalctl -u nsmon-panel -u nsmon-agent -f
```

## Securitate

- Login cu user și parolă (hash), sesiune 12h, blocare 10 minute după 5 încercări greșite.
- Agenții ascultă pe **8111/TCP (HTTPS)** și acceptă numai IP-ul panoului și numai cererile cu token.
- Dacă ufw e activ, portul se deschide automat doar pentru IP-ul panoului. Dacă ai firewall la provider, deschide manual 8111 doar pentru IP-ul netstreaming.eu.
- Aplicația rulează ca user `nsmonitor`, fără shell. Prin sudo poate executa doar restart/start pentru serviciile detectate, `nginx -t`, `nginx -s reload` și `fail2ban-client status`.

## Note

- Serviciile sunt detectate automat după nume: nginx, astra, ffmpeg, relay, stream, watchdog, fail2ban, gunicorn, monitor, srt, nts, udpxy, jellyfin. Dacă adaugi servicii noi, rulează din nou scriptul serverului respectiv.
- `hls_path` e citit automat din configurația nginx.
- **Cloudflare:** adaugă un Cache Rule: URI Path începe cu `/monitor` → **Bypass cache**.
