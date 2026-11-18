# Syllabus Coverage (DS2005 Object Oriented Programming)

Every concept below is used for a real purpose in the project. Paths are relative to the project folder.

## Unit I - Classes and objects

| Concept | Where | Notes |
|---|---|---|
| Classes and objects | `core/Entity.h`, `core/Incident.h`, `core/RiskScore.h` | Every domain concept is a class |
| Access specifiers | every class | `public` interface, `private`/`protected` data (e.g. `Person::passwordHash` is private) |
| Constructors | `Incident` (3 constructors), `Entity` (default + parameterised) | `Incident(...)` delegates to another constructor |
| Destructors | `Entity::~Entity`, `Repository<T>::~Repository`, `SeverityCounts::~SeverityCounts` | Free memory / update counters |
| Copy constructor | `core/SeverityCounts.cpp` | Deep copy of a heap array; also copy assignment (rule of three) |
| `this` pointer | `Entity::setName` (returns `*this`), `Person::checkPassword`, `SeverityCounts::operator=` | Disambiguation, chaining, self-assignment check |
| Static members | `Entity::nextId/alive`, `Incident::nextId`, `Threat::detections`, `Logger::filePath/entries` | ID counters and shared state |
| Friend function | `incidentSummary()` and `operator<<`/`>>` in `core/Incident.h`; `operator<<` in `core/Asset.h` | Read private data |
| Friend class | `ReportWriter` is a friend of `SecurityManager` (`core/ReportWriter.cpp`) | Report printer reads private containers |
| Function overloading | `SecurityManager::scan` (3 versions), `SecurityManager::addAsset` (4 versions), `BruteForceThreat::detect(string/int)`, `DDoSThreat::detect(string/int)` | Same name, different parameters |
| Dynamic memory | `new Admin(...)`, `new MalwareThreat()` in `SecurityManager` ctor; `new int[4]` in `SeverityCounts`; `Repository<T>::add/remove` | Matching `delete` / `delete[]` in destructors |
| const correctness | `const` getters everywhere, `const std::string&` parameters, `const Repository<Asset>&` getter | e.g. `Asset::getIp() const`, `SecurityManager::getStats() const` |

## Unit II - Inheritance and polymorphism

| Concept | Where | Notes |
|---|---|---|
| Single inheritance | `Person : Entity`, `MalwareThreat : Threat`, `Workstation : Asset` | |
| Multilevel inheritance | `Entity -> Person -> Employee -> SecurityOfficer` | |
| Hierarchical inheritance | `Asset -> Workstation / Server / Router`; `Threat -> Malware / Phishing / BruteForce / DDoS` | One base, many children |
| Multiple inheritance | `Server : Asset, Monitored` and `Router : Asset, Monitored` (`core/Asset.h`); `SecurityOfficer : Employee, Admin` | |
| Virtual base class (diamond) | `Person` is a virtual base of `Employee` and `Admin`; both feed `SecurityOfficer` (`core/Person.h`, `Employee.h`, `Admin.h`, `SecurityOfficer.h`) | `Person` exists once inside a `SecurityOfficer` |
| Function overriding | `Asset::describe`, `Person::describe`, `Threat::advice`, `roleName()` in each role | |
| Virtual functions | `Entity::describe`, `Person::canScan/...`, `Threat::advice` | Called through base pointers |
| Pure virtual / abstract classes | `Threat::detect` (abstract `Threat`), `Asset::type/details` (abstract `Asset`), `Person::roleName` (abstract `Person`), `TabPage::refresh` (GUI) | Cannot be instantiated |
| Virtual destructors | `Entity`, `Threat`, `Monitored` | `delete t` on a `Threat*` runs the derived destructor |
| Upcasting | `users["admin"] = new Admin(...)` (`Person*`), `threats.push_back(new MalwareThreat())` (`Threat*`), `assets += new Server(...)` | `SecurityManager::SecurityManager()` |
| Downcasting with `dynamic_cast` | `SecurityManager::findThreat<T>()`, `recordThreat` (cross-cast `Asset*` -> `Monitored*`), `AssetsTab::refresh`, `ReportWriter::build` (`SecurityOfficer*`) | Returns `nullptr` when the type does not match |

## Unit III - Templates, operators, STL

| Concept | Where | Notes |
|---|---|---|
| Class template | `Repository<T>` (`core/Repository.h`) | Owns heap objects: `add`, `remove`, `findById`, `findIf`, `operator[]`, `operator+=` |
| Function template | `util::clampValue<T>`, `util::countIf<Container, Test>` (`core/Utils.h`); member template `SecurityManager::findThreat<T>()`; `guarded<Action>()` in `gui/GuiHelpers.h` | |
| `operator<<` and `operator>>` | `Incident` (text export/import), `Asset`, `RiskScore` | `operator>>` parses one `id|title|...` line |
| `operator==`, `operator<` | `Incident` (priority order), `Asset` (same IP / name order) | Used by `std::sort` and duplicate checks |
| `operator+`, `+=`, `>` | `RiskScore` (`core/RiskScore.cpp`) | Overall risk = sum of open incident risks |
| `operator[]`, `operator+=` | `Repository<T>` | |
| Namespaces and `::` | `namespace cyber`, nested `cyber::util`, `theme::` (GUI), `Entity::liveCount()`, `Logger::info()` | |
| `vector` | scan results, `searchAssets`, `Repository` storage | |
| `list` | `SecurityManager::incidents` | Stable references while incidents are added |
| `map` | `users`, `failedLogins`, `threatStats` | |
| `set` | `blocked` sources, `MalwareThreat::signatures` | |
| `stack` | `undoStack` (undo-resolve, last in first out) | `SecurityManager::undoResolve` |
| `queue` | `scanQueue` (first in first out) | `queueSample` / `runQueue` |
| STL algorithms | `std::sort` (`searchAssets`, `ReportWriter`), `std::copy_if` (`searchAssets`), `std::find_if` (`findIncident`), `std::transform` (`util::toLower`), `std::equal` (file magic) | |

## Unit IV - Exceptions and files

| Concept | Where | Notes |
|---|---|---|
| Custom exception hierarchy | `core/Exceptions.h`: `CyberException : std::runtime_error`, with `AuthException`, `AccessDeniedException`, `ValidationException`, `NotFoundException`, `ThreatException`, `FileException` | All derive from `std::exception` |
| try / catch / throw | `SecurityManager::login`, `readBinary`, `autoLoad`; `guarded()` in `gui/GuiHelpers.h`; `LoginWindow::attemptLogin` | |
| Stack unwinding | `ScanGuard` in `core/SecurityManager.cpp` logs "Scan finished" even when `scan()` throws; `Asset` constructor throws after `Entity` is built and `Entity` is destroyed correctly | |
| GUI error message boxes | `guarded()` calls `fl_alert` with `e.what()` | |
| Text file I/O | `Logger` (append), `exportIncidents` / `importIncidents`, `saveReport`, `Logger::readAll` | |
| Binary file I/O | `Incident::writeBinary/readBinary` (fixed-size `IncidentRecord`), `SecurityManager::writeBinary/readBinary` with `CSH1` header | `incidents.dat` |
| File open failures | every `ifstream`/`ofstream` is checked and throws `FileException` | |
| Corrupt files | wrong magic header, negative count, truncated record -> `FileException`; the old data is left untouched (file is read fully before swapping) | tested in `tests/core_tests.cpp` |

## New in the latest version

| Concept | Where | Notes |
|---|---|---|
| Inheritance + overriding | `core/LinkThreat.h` (`LinkThreat : Threat`) | Link checker overrides `detect`, `advice`, `explanation` |
| Abstract class, hierarchy | `core/VaultItem.h`, `SecureNote.h`, `PasswordEntry.h` | Items in the Safe Box |
| Class template reuse | `core/Vault.h`: `Repository<VaultItem>` | Same template now owns Safe Box items |
| Static member functions | `PasswordEntry::strength/generate`, `XorCipher` (a plain class) | No object needed |
| Binary file I/O | `core/Vault.cpp`, `core/VaultItem.cpp` (`bytes::putText/getText`) | Magic header `CSV1`, hashed password check, scrambled payload |
| Encapsulation, RAII | `Vault` (private key wiped in `lock()`, `~Vault`) | Copying is deleted |
| New exception | `VaultLockedException` (`core/Exceptions.h`) | Touching a locked box |
| STL set / vector | `LinkThreat` (`badSites`, `scammerWords`) | |
| Custom widgets | `gui/StatusBanner`, `LockIcon`, `RiskGauge` ... | Subclasses of `Fl_Widget` overriding `draw()` |
| Concept guide | `gui/ConceptGuide.cpp`, `ConceptPanel.cpp` | The (i) button on every page |

## Two roles and employee privacy

| Concept | Where | Notes |
|---|---|---|
| Virtual function overriding for privacy | `Person::nameForOthers()` (`core/Person.h`), overridden in `Employee` (`core/Employee.h`) | Admins see `e******e`, never the real employee name |
| Diamond kept for Unit II | `core/SecurityOfficer.h` | Not a login role any more, still demonstrates the virtual base class |
| String helpers (namespace `util`) | `maskName`, `replaceWord` in `core/Utils.h` | Hide names inside logs and reports |
| Role checks | `canManageUsers()`, `canManageAssets()` ... | Only Admin and Employee exist now |

## Newest features

| Concept | Where | Notes |
|---|---|---|
| Class with operator overloading | `core/Password.h`: `operator<`, `==`, `+`, `<<` | Strength score, rating and tip; weak passwords refused when adding a user |
| Operator overloading `+` and `<`, STL `sort` | `core/AssetRisk.h`, `SecurityManager::riskRanking()` | Risk per device, ranked riskiest first |
| Abstract class + polymorphism (command pattern) | `core/AssetCommand.h`: `AssetCommand`, `AddAssetCommand`, `RemoveAssetCommand`, `EditAssetCommand` | Undo / redo of device changes |
| Two STL stacks | `SecurityManager::assetUndo`, `assetRedo` (`std::stack<std::unique_ptr<AssetCommand>>`) | A new change clears the redo stack |
| `std::set` | `Asset::passed` (checklist items that are done) | Compliance percentage |
| `std::vector` of structs + `operator<<` | `core/Incident.h`: `IncidentEvent`, `Incident::events` | Incident timeline |
| Versioned binary file | `core/Incident.cpp`, `SecurityManager.cpp` (`kMagicV1` / `kMagicV2`) | New files store the timeline; old ones still load |
| Text file reading + `std::map` | `core/AuditTrail.cpp`, `SecurityManager::auditView()` | Filter the log by level or user; counters per level |
| File handling + `std::map` + function templates | `core/LogAnalyzer.cpp`, `util::countUp`, `util::topCounts` (`core/Utils.h`) | Failed logins, port scans, dangerous commands |
| Callback with `std::function` | `SecurityManager::setAlertHandler()`, `MainWindow::raiseAlert()` | Core reports a CRITICAL threat without knowing the GUI |
| Custom widgets | `gui/NetworkMap.cpp`, `AlertBar.cpp`, `Toast.cpp`, `SplashWindow.cpp`, `DataTable.cpp` | Subclasses of FLTK classes overriding `draw()` / `handle()`; FLTK timers |
| Theme as data | `gui/Theme.h` `setPalette()`, `main.cpp` `App::switchTheme()` | Dark / light switch by rebuilding the windows |
