# 📦 Dockerized Application

This project uses Docker Compose to deploy a web schedule

---
## ⚙️ Setup Instructions

### 1. Configure Environment Variables

Copy the `.env_example` file and rename it to `.env`:
### 2. Edit the `.env` file and set following values:
- BACKEND_IP - any ip address from the 172.28.0.0/16 subnet, **except**
	- 172.28.0.2
	- 172.28.0.3
	- 172.28.0.5
	- ✅ **Recommended IP:** `172.28.0.4`
- DATABASE - name of your database
- USERNAME - database username
- USERPASSWORD - database user password
---
## 2. Prepare the Database Dump
### Place your database dump file in the **same directory** as `docker-compose.yml` and rename it to: `database.dump`
## 🚀 Run the Application
- Navigate to the project directory:
	`cd your-project-folder`
- Start the Docker containers:
	`docker compose up --build -d`
- After a few seconds, open your browser and go to:
	`http://localhost:3000`
## 🧹 Stopping and Cleaning Up
### To stop the containers: `docker compose down`
### To stop and remove all containers, images, and volumes: `docker compose down --volumes --rmi all`
## 📝 Notes
- Make sure the `BACKEND_IP` in `.env` does not conflict with restricted IPs.
- If the database doesn't connect, check your dump file, environment variables, and access rights.