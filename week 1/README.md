# Week 1: Security Assessment  
## OWASP Juice Shop Web Application

---

## 📌 Objective

The objective of **Week 1 – Security Assessment** is to understand the OWASP Juice Shop application and perform an initial security assessment to identify common web application vulnerabilities. This phase focuses on reconnaissance, application mapping, and basic vulnerability identification.

---

## 🧪 Target Application

- **Application Name:** OWASP Juice Shop
- **Application Type:** Intentionally vulnerable web application
- **Technology Stack:** Node.js, Express.js
- **Target URL:** http://localhost:3000
- **Testing Scope:** Web application only
- **Authorization:** OWASP Juice Shop is designed for legal security testing

---

## 🛠 Tools Used

| Tool | Purpose |
|----|----|
| Web Browser | Manual application testing |
| Browser Developer Tools | Client-side analysis |
| OWASP ZAP | Automated vulnerability scanning |
| Burp Suite / ZAP (Optional) | Request inspection |

---

## 🔍 Tasks Performed

### 1️⃣ Application Understanding
- Explored the application interface
- Identified key functionalities
- Mapped user workflows
- Reviewed authentication and user interaction points

### 2️⃣ Attack Surface Mapping
- Login and registration forms
- Search functionality
- Feedback form
- Basket and checkout pages
- User profile page
- API endpoints

### 3️⃣ Manual Vulnerability Assessment
- Tested input fields for malicious payloads
- Observed application behavior
- Checked for improper validation
- Analyzed client-side logic

### 4️⃣ Automated Scanning
- Configured OWASP ZAP
- Performed passive scanning
- Identified common web vulnerabilities

---

## 🚨 Vulnerabilities Identified

| Vulnerability | Description | Severity |
|--------------|------------|----------|
| SQL Injection | User input accepted SQL payloads | High |
| Cross-Site Scripting (XSS) | JavaScript execution via input | Medium |
| Broken Authentication | Weak authentication controls | High |
| Sensitive Data Exposure | Data visible in responses | Medium |

---

## 📸 Evidence Collected

- Application screenshots
- Input testing results
- OWASP ZAP alerts
- Browser DevTools output

*(Screenshots stored in the Screenshots directory)*

---

## 📊 Results Summary

- Multiple OWASP Top 10 vulnerabilities identified
- Lack of input validation and sanitization
- Weak authentication mechanisms
- Insufficient security headers

---

## 🎯 Outcome

Week 1 successfully established a security baseline and provided a clear understanding of the application's weaknesses. The findings from this phase were used to guide remediation efforts in Week 2.

---

## ⚠️ Disclaimer

This assessment was performed on OWASP Juice Shop, an intentionally vulnerable application, in a controlled environment for educational purposes only.

---

## ✅ Week 1 Status

✔ Application assessed  
✔ Vulnerabilities identified  
✔ Evidence documented  
✔ Ready for remediation phase  

---
