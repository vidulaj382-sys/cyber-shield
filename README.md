# Cyber Shield: Cybersecurity and Management System

DS2005 Object Oriented Programming project (VIT). A desktop app written in C++17 with an FLTK GUI.

It manages IT assets, scans for threats (Malware, Phishing, Brute-Force, DDoS), tracks security
incidents, produces a security report and keeps an activity log. Two roles (Admin and Employee) decide who may do what.

## Project layout

```
core/    pure C++ logic, no FLTK        (classes, inheritance, templates, exceptions, files)
gui/     FLTK windows and tabs          (only display data and call core)
tests/   core_tests.cpp                 (plain asserts, no framework)
main.cpp wires the core to the windows
build.sh builds and runs the tests, then builds CyberShield.exe
SYLLABUS.md  every Unit I-IV concept mapped to file and class
UML.md       Mermaid class diagrams
```

## Build and run

You need MSYS2 with the UCRT64 toolchain:

```
pacman -S mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-fltk
```

Build (from anywhere in Windows):

```
C:\msys64\usr\bin\bash.exe -lc "MSYSTEM=UCRT64 sh /c/Users/Mankeshwari/CyberShield/build.sh"
```

`build.sh` compiles with `-Wall -Wextra` (no warnings), builds and runs `core_tests.exe`, then builds
`CyberShield.exe`. Run it by double-clicking `CyberShield.exe` (start it from its own folder so it
finds `incidents.dat` and writes `cybershield.log` next to it).

## Sample data

- **Quick:** log in as `admin` and press **Load sample data** on the Home page. It adds 6 devices and 8 problems
  (3 already fixed), so the dashboard, chart and gauge have something to show. Pressing it again adds nothing.
- **Files:** the `sample_data/` folder has `incidents.txt` (to try *Import from text file*), `threat_samples.txt`
  (texts to paste into the Attack Detector) and `links.txt` (safe, tricky and dangerous links). Its `README.txt`
  explains each file. `tests/core_tests.cpp` checks that every sample behaves as described.

## Demo logins

| User | Password | Role | Can do |
|---|---|---|---|
| `admin` | `admin123` | Admin | everything: devices, users, scans, fixing problems, load/import data, sample data |
| `employee` | `emp123` | Employee | look at the dashboard and devices, report problems, check links, use their own Safe Box |

Five wrong passwords for a user lock that account until the app is restarted (a brute-force
incident is created automatically).

## Look and feel

Sidebar navigation, Segoe UI / Consolas fonts, flat rounded buttons with hover (`FlatButton`), a drawn shield
logo (`ShieldLogo`), a styled login screen with one-click demo accounts, and one shared dark theme (`gui/Theme.h`).

## Features

1. **Login** with two roles (Admin and Employee). Passwords are stored only as a salted hash (`util::hashPassword`).
2. **Dashboard**: 4 stat cards, a bar chart of open incidents by severity (`gui/BarChart.cpp`), a risk gauge
   (`gui/RiskGauge.cpp`) and the newest incidents. All are custom `Fl_Widget` classes drawn with FLTK functions.
3. **Assets**: add / remove / list Workstations, Servers and Routers (IP, criticality 1-5), live search by name.
4. **Threats**: scan text, an IP, or numbers (failed logins, requests/sec). Results appear in a coloured
   console. Serious detections create incidents automatically. A FIFO queue holds pending scans.
5. **Incidents**: report, resolve and undo-resolve (stack), severity colours, save/load (binary `incidents.dat`),
   export/import (text `incidents.txt`).
6. **Report**: generated security report, saved to `security_report.txt`.
7. **Log**: every action goes to `cybershield.log`; the Log tab shows it.
8. **Users** (Admin only): add and remove accounts.
9. **Link Checker**: paste a web link and get Safe / Be careful / Dangerous with plain-English reasons
   (`core/LinkThreat.cpp`). A dangerous link creates a problem automatically.
10. **Safe Box**: a locked place for secret notes (documents) and saved passwords. One secret password
    unlocks it. Items are scrambled (`core/XorCipher.cpp`) in a binary file `vault_<username>.dat`. It has a
    password strength meter and a password generator, and it locks itself on logout.
11. **Concepts on this page**: the blue (i) button on every page opens a column that lists the OOP concepts
    used on that page, WHERE they are in the code and WHAT they are used for (`gui/ConceptGuide.cpp`).
    Use it to explain the project to your teacher.

The app uses plain words (Home, My Devices, Attack Detector, Problems ...) so that anyone, even a 10 year old,
can understand each page.

### Newest features

12. **Password strength checker** (People page): a live score, rating and tip while you type a new user's
    password; weak passwords are refused. `core/Password.h` is a class with `operator<`, `==`, `+` and `<<`.
13. **Risk score per device** (My Devices): importance + alerts + open problems + missing checks = 0-100, shown
    as a colour-coded row (`core/AssetRisk.h`, `operator+`, `operator<`, `std::sort`).
14. **Security checklist per device**: six checks such as "Firewall is on" with a compliance percentage.
15. **Undo / redo for device edits** (add, remove, change): two stacks of command objects
    (`core/AssetCommand.h`).
16. **Network Map**: a custom-drawn diagram, devices as nodes coloured by risk; click a node for details.
17. **Incident timeline** (Problems page): reported, assigned, fixed and fix-undone events with time and person.
    Old `incidents.dat` files (format `CSH1`) still open.
18. **Audit trail** (History page): filter the activity log by level (INFO / WARN / ERROR) or by user.
19. **Log Analyzer**: open any text log file and mark failed logins, port scans and dangerous commands, with
    counters per kind and per IP address (`core/LogAnalyzer.cpp`). `sample_data/server.log` is an example.
20. **Click a column name to sort, type to search** in every table (`gui/DataTable.cpp`).
21. **Dark / light theme** button in the header.
22. **Splash screen** at start, and for every CRITICAL threat a **blinking red bar**, a **pop-up toast** and a
    warning **sound**.

## 2-minute viva demo script

1. **(0:00) Login.** Type `employee` with a wrong password: error box (AuthException). Log in as `employee/emp123`.
   Show that Threats > *Scan Now* is greyed out and Assets has a "can only view" note (roles = virtual functions
   `canScan()`, `canManageAssets()`). Report an incident on the Incidents tab. Logout.
2. **(0:30) Admin.** Log in as `admin/admin123`. **Dashboard**: explain the cards and the bar chart
   (custom widget, `SeverityCounts` with `new[]`/copy constructor, `RiskScore` with `operator+`).
3. **(0:50) Assets.** Add a Router `gw-02`, `10.0.0.99`, criticality 4. Type in Search to filter. Try adding it
   again: ValidationException box. (`Repository<T>` template, `Asset` abstract class, `operator==`.)
4. **(1:10) Threats.** Press *Scan Now* with the phishing sample, then paste `trojan.exe.zip` and scan, then
   `Scan Numbers` (7 failed logins, 2500 requests/sec). Show red lines in the console and the new incidents.
   (Polymorphism: `Threat*` vector calls the right `detect()`; overloaded `scan()` versions; `dynamic_cast`.)
5. **(1:30) Incidents.** Resolve one, then *Undo Last Resolve* (stack). Click *Save (binary)*, then *Export (text)*.
   Mention the corrupt-file protection (`FileException`, magic header).
6. **(1:45) Report and Log.** Open Report, click *Save*. Open the Log tab. Finish by pointing to `SYLLABUS.md`
   and the diamond `Person -> Employee/Admin -> SecurityOfficer` in `UML.md`.

## Design decisions (simple choices made for you)

- **Users are not saved** to disk; the two demo users (admin and employee) are created at startup and users added in the Users tab
  last until the app closes. Incidents are saved automatically to `incidents.dat` on exit and loaded on start.
- **First start** (no valid `incidents.dat`): three sample incidents are created so the dashboard is not empty.
- **Only two roles:** Admin (handles everything) and Employee. The old Analyst role was removed. The class
  `SecurityOfficer` is kept in `core/` only to show the virtual-base diamond (`Person -> Employee/Admin ->
  SecurityOfficer`) for Unit II; it is not used as a login role.
- **Employee privacy:** an Admin never sees employee details directly. Employee names appear in a hidden form
  (for example `e******e`) on the People page, in problem lists, in the report and in the history log, together
  with only a count of the problems they reported. This is done with the virtual function
  `Person::nameForOthers()`, which `Employee` overrides. Everyone still sees their own name, and each user's Safe
  Box can only be opened with that user's own secret password.
- **IP scanning** is done by text matching: two known-bad IPs (`185.220.101.1`, `45.155.205.233`) are part of
  the malware signature list. Paste an IP into *Sample text* to test it.
- **Blocked sources**: a detected source is added to a block list (shown in the report), and locked accounts stay
  locked until restart.
- **Passwords** use a simple salted djb2 hash, fine for a course project but not production security.
- **Ids** come from a shared static counter in `Entity`, so asset ids start after the three user ids.
- **Safe Box encryption** is a simple teaching cipher (a keyed XOR stream) plus a hashed password check. It
  is good enough to show the idea, but real programs should use AES. If the secret password is forgotten the
  Safe Box cannot be opened.
- **Files** (`incidents.dat`, `vault_<user>.dat`, `incidents.txt`, `security_report.txt`, `cybershield.log`) use fixed names in the
  program folder, no file dialogs, to keep the code easy to read.
