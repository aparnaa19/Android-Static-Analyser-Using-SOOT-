# Android Static Analyzer using Soot

## What is Static Analysis?

When you install an app on your phone, you usually trust it to do what it says. But what if a flashlight app is secretly tracking your location? Or a calculator app is sending your messages without you knowing?

**Static analysis** is a way to inspect an app's behavior **without actually running it**. We read the app's code directly and look for suspicious or sensitive behavior — like a detective examining evidence before making a move.

---

## What is this project?

This project is a static analyzer for Android applications built using **Soot** — a Java framework for analyzing Android and Java programs.

Given an Android app (`.apk` file), this tool:
- Finds all **sensitive API calls** inside the app
- Records how many times each API is called and which functions call it
- Generates a **Control Flow Graph (CFG)** for every function in the app

---

## What are Sensitive APIs?

Android apps need special **permissions** to access things like your GPS, camera, contacts, or microphone. The APIs that require these permissions are called **sensitive APIs**.

Examples:
| API | What it accesses |
|---|---|
| `getLastLocation()` | Your GPS location |
| `sendTextMessage()` | Sends SMS messages |
| `getDeviceId()` | Your unique device ID |
| `getContacts()` | Your contact list |

If an app is secretly calling these APIs without a clear reason, that's a **red flag**.

---

## Where do Sensitive API lists come from?

In this project, the sensitive API list was provided as a CSV file. But in real life, these lists come from:

- **Android Documentation** — Google officially documents which APIs require permissions
- **Research tools** like PScout and Axplorer — academic tools that automatically extract permission-API mappings from Android source code
- **Android Source Code** — developers can analyze the Android OS itself to find protected APIs
- **Security tools** like Androguard or FlowDroid — which have built-in sensitive API lists

---

## How does the analyzer work?

Think of an APK like a **building**:
- **Classes** = Floors
- **Methods** = Rooms on each floor
- **Statements** = Furniture inside each room

The analyzer walks through:
```
Every floor (class)
    → Every room (method)
        → Every piece of furniture (statement)
```

In each room it does two things:
1. **Checks if any statement calls a sensitive API** → records it
2. **Draws a map of the room** → that's the Control Flow Graph

---

## What is a Control Flow Graph (CFG)?

A CFG is a visual map of all possible paths execution can take through a function.

- Each **node** = a statement
- Each **arrow** = possible flow of execution

Example CFG for a simple `<init>` method:
```
[this := @this: LocationTest]
            ↓
[specialinvoke this.<Activity: void <init>()>()]
            ↓
        [return]
```

CFGs are saved as `.dot` files which can be visualized at https://dreampuf.github.io/GraphvizOnline

---

## Real World Application

This is exactly what **real security analysts** do:

1. Get a suspicious APK (malware, spyware)
2. Run static analysis with a sensitive API list
3. Find which sensitive APIs the app secretly calls
4. Flag it as malicious if needed

**Real examples of malicious apps caught this way:**
- A flashlight app calling `getLastLocation()` → **spyware**
- A calculator app calling `sendTextMessage()` → **malware**
- A game calling `getDeviceId()` and `getContacts()` → **data harvesting**

The only difference between this project and real-world analysis is that production tools use more advanced techniques like **taint analysis** and **data flow analysis**.

---

## Output

### 1. Sensitive API Usage (`sensitive_api_usage.txt`)
```
requestLocationUpdates:1:onResume()
removeUpdates:1:onPause()
getLastLocation:1:setMessage()
getSystemService:1:onResume()
```
Format: `API_name:frequency:residing_functions`

### 2. Control Flow Graph files (`.dot`)
One `.dot` file is generated per function, saved in the output folder.

---

## Tools Used
- **Java** — programming language
- **Soot 4.7.1** — static analysis framework
- **Android SDK** — required to resolve Android framework classes
- **IntelliJ IDEA** — IDE used for development
- **Graphviz Online** — for visualizing `.dot` CFG files
