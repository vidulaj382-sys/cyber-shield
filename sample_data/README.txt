SAMPLE DATA FOR CYBER SHIELD
============================

1. Quick way: log in as admin and press "Load sample data" on the Home page.
   It adds 6 devices and 8 problems (3 already fixed). Pressing it twice does nothing extra.

2. incidents.txt  - 8 problems in the app's text format (id|title|device|seriousness|status|reporter).
   To try "Import from text file": copy it into the program folder (next to CyberShield.exe)
   and press "Import from text file" on the Problems page (Admin only).
   seriousness: 1 Low, 2 Medium, 3 High, 4 Critical.  status: 0 = open, 1 = fixed.

3. threat_samples.txt - texts and numbers to try on the Attack Detector page.
4. links.txt          - safe, tricky and dangerous links to try on the Link Checker page.
5. server.log         - a 24-line server log for the Log Analyzer page (Admin only):
                        9 failed logins, 8 port-scan lines and 2 dangerous commands are hidden in it.

Demo logins:  admin/admin123   employee/emp123
