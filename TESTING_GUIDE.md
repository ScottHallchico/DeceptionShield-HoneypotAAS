# DeceptionShield Dashboard Testing Guide

This guide walks you through testing every feature and functionality of the **DeceptionShield** frontend web application.

---

## 1. Authentication & Login
By default, the platform is secured. 
- **Action:** Open `http://localhost:3000` (or `http://localhost:8081`).
- **Expected:** You should be presented with a login screen.
- **Test:** Enter the credentials:
  - **Email:** `admin@honeypot.io`
  - **Password:** `honeypot-admin-2024`
- **Result:** You should successfully authenticate and be redirected to the main `/dashboard` page.

---

## 2. Global Connection Status
The dashboard relies on WebSockets for real-time updates.
- **Action:** Look at the top navigation bar or header.
- **Test:** Verify the connection status indicator.
- **Result:** It should display a green **"Live"** or **"Connected"** status. (If it says "Offline" or "Reconnecting", the backend WebSocket `ws://localhost:8000/ws/live` is unreachable).

---

## 3. The Main Dashboard (Real-time Events)
The main dashboard gives a birds-eye view of active threats.

- **Action:** Navigate to **Dashboard** (Home).
- **Test A (Metrics):** Look at the top KPI cards (Total Events, Active Attackers, Active Honeypots). These should display numbers populated from the database.
- **Test B (Charts):** Ensure the charts (e.g., Attack Trends over Time, Top Targeted Honeypots) render properly and display data.
- **Test C (Live Feed):** 
  1. Open a terminal and run `curl.exe -X POST http://localhost:8080/wp-login.php -d "log=admin&pwd=test"`.
  2. Switch back to the dashboard immediately.
  3. **Result:** The "Live Events" table or feed should update **instantly** without refreshing the page, showing the new HTTP attack.

---

## 4. Attackers Profiling
This page tracks distinct IP addresses and profiles their behavior.

- **Action:** Navigate to the **Attackers** tab.
- **Test A (List):** You should see a table or grid of attacker IP addresses, sorted by Threat Score or most recent activity.
- **Test B (GeoIP):** If the IP is public (e.g., `8.8.8.8`), you should see a country flag or location data. *(Note: Localhost attacks like `127.0.0.1` will not have a country).*
- **Test C (Drilldown):** Click on an attacker's IP address.
  - **Result:** It should open a detailed view showing every command they typed, URLs they accessed, and which honeypots they triggered.

---

## 5. Blocklist Management
This page allows you to manually ban IPs or view auto-banned IPs.

- **Action:** Navigate to the **Blocklist** tab.
- **Test A (View):** Ensure you can see a list of currently blocked IPs and their expiration times.
- **Test B (Add Block):**
  1. Click "Add New Block" or "Block IP".
  2. Enter a test IP: `9.9.9.9` and set a reason: `Manual Dashboard Test`.
  3. Click Save.
  4. **Result:** The IP should instantly appear in the Blocklist table.
- **Test C (Remove Block):**
  1. Click the "Unblock" or "Delete" icon next to `9.9.9.9`.
  2. **Result:** The IP should disappear from the list.

---

## 6. Detection Rules
This page manages custom alert rules (e.g., "Alert if someone types 'wget'").

- **Action:** Navigate to the **Rules** tab.
- **Test A (Create Rule):** 
  1. Click "Create Rule".
  2. Set Name: `Test Wget Rule`.
  3. Set Pattern: `wget`.
  4. Set Action: `Alert` (or `Block`).
  5. Save the rule.
  6. **Result:** The new rule should be visible in the table.
- **Test B (Toggle Status):**
  1. Use the toggle switch next to the rule to disable it.
  2. Refresh the page.
  3. **Result:** The rule should remain disabled (verifying it saved to the database).

---

## 7. AI Security Assistant (Chatbot)
If configured with an API key, you can chat with the data.

- **Action:** Click on the AI Assistant chat widget (usually a floating button or a dedicated tab).
- **Test A:** Type: *"How many attacks did we receive today?"*
- **Test B:** Type: *"Are there any specific IPs I should block?"*
- **Result:** The AI should respond with insights based on the real data stored in the dashboard. *(If it errors out, verify the `Anthropic` or `OpenAI` API keys are set in `backend/.env`)*.

---

## 8. Mobile Responsiveness (UI/UX)
- **Action:** Resize your browser window to simulate a mobile phone, or open the browser's Developer Tools and toggle "Device Toolbar".
- **Result:** The sidebar should collapse into a hamburger menu, and charts/tables should resize gracefully to fit the smaller screen.
