# UPI Shield

UPI Shield is a context-aware fraud detection prototype for UPI digital payments. The repository contains a Spring Boot backend and an Android Java client.

## Prerequisites

- JDK 21
- Docker Desktop
- Android SDK 34

## Run the backend

```powershell
cd backend
$env:JAVA_HOME="C:\Program Files\Android\Android Studio\jbr"
.\mvnw.cmd test
.\mvnw.cmd spring-boot:run
```

The API listens on `http://localhost:8080`.

## Run with Docker Compose

```powershell
docker compose up --build
```

Docker starts PostgreSQL, Redis, and the Spring Boot backend.

## Run the Android app

Open the project root in Android Studio, allow the Gradle sync, and run the `app` configuration on an emulator or device.

The Android app uses `http://10.0.2.2:8080` for an emulator. For a physical device, replace the base URL in `app/src/main/java/com/upishield/android/MainActivity.java` with the backend host accessible from that device.

## Security behavior

- Authentication uses JWT bearer tokens.
- Profile and preference routes require authentication.
- Admin moderation routes require `MODERATOR_ADMIN` or `ADMIN`.
- Message, URL, QR, and risk payloads reject PIN, OTP, CVV, and password patterns.
- URL redirect tracing validates private, loopback, link-local, and local host targets.
- Raw messages and QR payloads are not stored as part of risk scan history.
