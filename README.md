Secure Multiprocess TCP Client-Server Application

A secure TCP client-server application developed for the **IE2102 - Network Programming** module at the Sri Lanka Institute of Information Technology (SLIIT).

📌 Project Overview

This project demonstrates the implementation of a secure, multiprocessing TCP server written in **C** and a Python-based client. The server supports multiple concurrent clients using the `fork()` system call and implements a custom TCP protocol with authentication, session management, security features, and audit logging.

🚀 Features

- Custom TCP Protocol with explicit message framing
- Multiprocessing server using `fork()`
- Concurrent client handling
- User Registration and Login
- Salted password hashing
- Session token authentication
- Session timeout after inactivity
- Rate limiting
- Login brute-force protection
- Username validation
- Payload overflow protection
- Persistent audit logging
- Graceful child process cleanup using `SIGCHLD`

🛠 Technologies Used

Server
- C
- GCC
- POSIX Socket Programming
- Linux System Calls
- Makefile

Client
- Python 3
- Socket Library

---

📂 Project Structure

```
.
├── server_0936.c
├── client_0936.py
├── Makefile_0936
├── server_IT24100936.log
├── README.md
└── Report/
```

---

⚙️ Build

Compile the server using:

```bash
make -f Makefile_0936
```

Or manually:

```bash
gcc server_0936.c -o server
```

---

▶️ Running

Start the server:

```bash
./server
```

Run the client:

```bash
python3 client_0936.py
```

---

📡 Supported Commands

- REGISTER
- LOGIN
- LOGOUT

Example:

```
REGISTER yehen123

LOGIN yehen123

LOGOUT
```

---

🔒 Security Features

- Passwords are never stored as plain text.
- Salted hashing for credentials.
- Session token authentication.
- Session expiration after inactivity.
- Rate limiting to prevent abuse.
- Brute-force login protection.
- Input validation.
- Payload size verification.

---

📝 Logging

The server records:

- Timestamp
- Client IP Address
- Client Port
- Process ID (PID)
- Username
- Executed command
- Result of operation

---

📖 Learning Outcomes

This project demonstrates knowledge of:

- TCP Socket Programming
- Client-Server Architecture
- Process Management using `fork()`
- Interprocess Communication
- Authentication & Authorization
- Secure Programming Practices
- Network Protocol Design

---

👨‍💻 Author

**Yehen Seniru**

SLIIT  
Faculty of Computing

---

📄 License

This project was developed for academic purposes as part of the IE2102 - Network Programming module.
