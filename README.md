# 🛡️ C++ Honeypot – `ghostgate`

A lightweight, customizable honeypot written in C++ that mimics common network services (like SSH) to monitor and log unauthorized access attempts. This project helps you understand socket programming, network security, and low-level systems programming.

---

## 🚀 Features

- 🔌 Listens on configurable TCP ports
- 🎭 Simulates fake login prompts (e.g., SSH)
- 📝 Logs IP, port, and credentials
- 🧵 Easily extendable with multithreading
- 📦 Minimal dependencies (pure C++ / POSIX)

---

## 📸 Demo

```bash
$ nc 127.0.0.1 4444
Fake SSH Service
Username: admin
Password: pass123
Access Denied.
