// server.js
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const multer = require("multer");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const HOST = process.env.HOST || "localhost";
const PORT = process.env.PORT || 4000;
const SECRET_KEY = process.env.SECRET_KEY;
const JWT_SECRET = process.env.JWT_SECRET || "my_jwt_secret";
const ALGORITHM = "aes-256-cbc";


const upload = multer({ dest: 'temp/' });




// ---------------------------
// Basic Middleware Setup
// ---------------------------
app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(bodyParser.json());
app.use(express.json());

// ---------------------------
// Security: JWT & RBAC Middleware
// ---------------------------
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(" ")[1];
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) return res.status(403).json({ message: "Forbidden" });
      req.user = user;
      next();
    });
  } else {
    res.status(401).json({ message: "Unauthorized" });
  }
};

const authorizeRoles = (...roles) => {
  return (req, res, next) => {
    if (req.user && roles.includes(req.user.role)) {
      next();
    } else {
      res.status(403).json({ message: "Forbidden: Insufficient role" });
    }
  };
};

// Ensure that a JSON file exists, otherwise create it with default content.
const ensureFileExists = (filePath, defaultContent) => {
    if (!fs.existsSync(filePath)) {
      fs.writeFileSync(filePath, JSON.stringify(defaultContent, null, 2), "utf-8");
      console.log(`🆕 Created missing file: ${filePath}`);
    }
  };

// ---------------------------
// File Paths & Default Data
// ---------------------------
const dataDir = path.join(__dirname, "data");
const jsonFiles = {
  users: "data/users.json",
  schedules: "data/schedules.json",
  attendance: "data/attendance.json",
  rooms: "data/rooms.json"
};
const defaultData = {
  users: [],
  schedules: {},
  attendance: {},
  rooms: {}
};

app.get("/attendance/summary", authenticateJWT, (req, res) => {
    const attendanceData = readJSONFile(jsonFiles.attendance);
    let summary = {};

    const aggregateAttendance = (data) => {
        let totalSessions = 0, totalPresent = 0, totalAbsent = 0;
        Object.keys(data).forEach(date => {
            const sessions = data[date];
            Object.keys(sessions).forEach(timeSlot => {
                totalSessions++;
                if (sessions[timeSlot].present) {
                    totalPresent++;
                } else {
                    totalAbsent++;
                }
            });
        });

        return {
            totalSessions,
            totalPresent,
            totalAbsent,
            percentagePresent: totalSessions > 0 ? ((totalPresent / totalSessions) * 100).toFixed(2) : "0.00"
        };
    };

    if (req.user.role === "Therapist") {
        const therapistName = req.user.name;
        const data = attendanceData[therapistName];
        if (!data) {
            return res.status(404).json({ success: false, message: "No attendance data found for your account." });
        }
        summary[therapistName] = aggregateAttendance(data);
    } else {
        Object.keys(attendanceData).forEach(therapistName => {
            summary[therapistName] = aggregateAttendance(attendanceData[therapistName]);
        });
    }

    res.status(200).json({ success: true, summary });
});

// ---------------------------
// Utility Functions (Encryption/Decryption)
// ---------------------------
const encryptFile = (filePath, password) => {
  try {
    const data = fs.readFileSync(filePath);
    const key = crypto.createHash("sha256").update(password).digest("base64").substr(0, 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    const encryptedData = Buffer.concat([cipher.update(data), cipher.final()]);
    fs.writeFileSync(filePath, Buffer.concat([iv, encryptedData]));
    console.log(`🔐 Encrypted: ${filePath}`);
  } catch (error) {
    console.error(`❌ Error encrypting ${filePath}: ${error.message}`);
  }
};

const decryptFile = (filePath, password) => {
  try {
    const data = fs.readFileSync(filePath);
    const key = crypto.createHash("sha256").update(password).digest("base64").substr(0, 32);
    const iv = data.slice(0, 16);
    const encryptedData = data.slice(16);
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    const decryptedData = Buffer.concat([decipher.update(encryptedData), decipher.final()]);
    fs.writeFileSync(filePath, decryptedData);
    console.log(`🔓 Decrypted: ${filePath}`);
  } catch (error) {
    console.error(`❌ Error decrypting ${filePath}: ${error.message}`);
  }
};

const readJSONFile = (filePath) => {
  try {
    const absolutePath = path.join(__dirname, filePath);
    if (!fs.existsSync(absolutePath)) {
      console.log(`⚠️ File ${filePath} does not exist.`);
      return {};
    }
    decryptFile(absolutePath, SECRET_KEY);
    const fileData = fs.readFileSync(absolutePath, "utf-8");
    return JSON.parse(fileData);
  } catch (error) {
    console.error(`❌ Error reading JSON file (${filePath}):`, error);
    return {};
  }
};

const writeJSONFile = (filePath, data) => {
  try {
    const absolutePath = path.join(__dirname, filePath);
    fs.writeFileSync(absolutePath, JSON.stringify(data, null, 2), "utf-8");
    encryptFile(absolutePath, SECRET_KEY);
    console.log(`✅ JSON file saved and encrypted: ${filePath}`);
  } catch (error) {
    console.error(`❌ Failed to write JSON file: ${filePath}, Error:`, error);
  }
};

const ensureDirectoryExists = (dirPath) => {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
    console.log(`📁 Created missing directory: ${dirPath}`);
  }
};

const ensureAllJSONFiles = () => {
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
    console.log("📁 Created missing data directory");
  }
  ensureFileExists(path.join(__dirname, jsonFiles.users), defaultData.users);
  ensureFileExists(path.join(__dirname, jsonFiles.schedules), defaultData.schedules);
  ensureFileExists(path.join(__dirname, jsonFiles.attendance), defaultData.attendance);
  ensureFileExists(path.join(__dirname, jsonFiles.rooms), defaultData.rooms);
  console.log("✅ All required JSON files are verified.");
};
ensureAllJSONFiles();

const encryptDocument = (filePath) => {
    try {
      const data = fs.readFileSync(filePath);
      const key = crypto.createHash("sha256").update(SECRET_KEY).digest("base64").substr(0, 32);
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
      const encryptedData = Buffer.concat([cipher.update(data), cipher.final()]);
      // Write IV + encrypted content back to file.
      fs.writeFileSync(filePath, Buffer.concat([iv, encryptedData]));
      console.log(`🔐 Document encrypted: ${filePath}`);
    } catch (error) {
      console.error(`❌ Error encrypting document ${filePath}: ${error.message}`);
    }
  };
  
  // Decrypt the file content and return the decrypted Buffer.
  const decryptDocument = (filePath) => {
    try {
      const data = fs.readFileSync(filePath);
      const key = crypto.createHash("sha256").update(SECRET_KEY).digest("base64").substr(0, 32);
      const iv = data.slice(0, 16);
      const encryptedData = data.slice(16);
      const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
      const decryptedData = Buffer.concat([decipher.update(encryptedData), decipher.final()]);
      return decryptedData;
    } catch (error) {
      console.error(`❌ Error decrypting document ${filePath}: ${error.message}`);
      return null;
    }
  }; 
 
// ---------------------------
// Scheduling Constants
// ---------------------------
const timeSlots = ["1:15", "2:00", "2:45", "3:45", "4:30", "5:15", "6:00", "6:45", "7:30", "8:15"];
const days = ["Δευτέρα", "Τρίτη", "Τετάρτη", "Πέμπτη", "Παρασκευή"];

// ---------------------------
// Audit Log Utility
// ---------------------------
const logAudit = (entry) => {
  const auditLogPath = path.join(__dirname, "data", "audit.log");
  const logEntry = `[${new Date().toISOString()}] ${entry}\n`;
  fs.appendFileSync(auditLogPath, logEntry, "utf-8");
};

// ---------------------------
// File & Document Utilities
// ---------------------------
const generateEncryptedFileName = (originalName) => {
  const ext = path.extname(originalName);
  const hash = crypto.createHash("sha256").update(originalName + Date.now().toString()).digest("hex");
  return `${hash}${ext}`;
};

// Setup multer storages with encrypted file names (stubs for now)
const storageAssessments = multer.diskStorage({
  destination: (req, file, cb) => {
    const { therapistName } = req.body;
    const assessmentsPath = path.join(__dirname, "data", "therapists", therapistName, "Αξιολογήσεις");
    ensureDirectoryExists(assessmentsPath);
    cb(null, assessmentsPath);
  },
  filename: (req, file, cb) => {
    cb(null, generateEncryptedFileName(file.originalname));
  }
});
const uploadAssessment = multer({ storage: storageAssessments });

const storageTemplates = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, "data", "templates", "Custom_Templates");
    ensureDirectoryExists(uploadPath);
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    cb(null, generateEncryptedFileName(`${req.body.therapistName}_Custom.docx`));
  }
});
const uploadTemplate = multer({ storage: storageTemplates });


// Endpoint for uploading therapist documents (e.g., documentation, assessments)
app.post("/upload-document", upload.single("file"), (req, res) => {
    const { therapistName, childName } = req.body;
    if (!req.file) {
      return res.status(400).json({ success: false, message: "No file uploaded." });
    }
    const users = readJSONFile(jsonFiles.users);
    const therapist = users.find(u => u.name === therapistName);
    if (!therapist) {
      return res.status(404).json({ success: false, message: "Therapist not found." });
    }
  
    // Determine the save path based on therapist's preference.
    let savePath;
    if (therapist.preference === "weekly") {
      savePath = path.join(__dirname, "data", "therapists", therapistName, "Weekly_Docs");
    } else {
      if (!childName) {
        return res.status(400).json({ success: false, message: "Child name is required for child-based documentation." });
      }
      savePath = path.join(__dirname, "data", "therapists", therapistName, "Child_Docs", childName);
    }
  
    // Ensure the directory exists
    fs.mkdirSync(savePath, { recursive: true });
  
    // Define the destination file path using an encrypted file name (your existing logic)
    const filePath = path.join(savePath, req.file.originalname); // Alternatively, use your encrypted file name generator
  
    // Move file to the correct directory
    fs.renameSync(req.file.path, filePath);
  
    // Encrypt the entire content of the file
// Encrypt the entire file content and write it back to disk.

  });

// ---------------------------
// Therapist Initialization
// ---------------------------
const createTherapistFolders = (therapistName) => {
  const basePath = path.join(__dirname, "data", "therapists", therapistName);
  ensureDirectoryExists(basePath);
  ["Αναφορές", "Child_Docs", "Weekly_Docs", "Αξιολογήσεις"].forEach((folder) => {
    ensureDirectoryExists(path.join(basePath, folder));
  });
};

const initializeTherapistSchedule = (therapistName) => {
  const schedules = readJSONFile(jsonFiles.schedules);
  if (!schedules[therapistName]) {
    schedules[therapistName] = {};
    timeSlots.forEach((time) => {
      schedules[therapistName][time] = {
        "Δευτέρα": "", "Τρίτη": "", "Τετάρτη": "", "Πέμπτη": "", "Παρασκευή": ""
      };
    });
    writeJSONFile(jsonFiles.schedules, schedules);
    console.log(`✅ Schedule initialized for ${therapistName}`);
  }
};

const initializeTherapistAttendance = (therapistName) => {
  const attendance = readJSONFile(jsonFiles.attendance);
  if (!attendance[therapistName]) {
    attendance[therapistName] = {};
    writeJSONFile(jsonFiles.attendance, attendance);
    console.log(`✅ Attendance initialized for ${therapistName}`);
  }
};

// ---------------------------
// Authentication Endpoint (Login)
// ---------------------------
app.post("/login", (req, res) => {
    const { name, password } = req.body;
  
    // Check if the user is the hardcoded Admin (from .env)
    if (name === process.env.ADMIN_NAME && password === process.env.ADMIN_PASSWORD) {
      const token = jwt.sign({ name, role: "Admin" }, JWT_SECRET, { expiresIn: "1h" });
      return res.json({ token });
    }
  
    // Otherwise, check normal users from JSON storage
    const users = readJSONFile(jsonFiles.users);
    const user = users.find(u => u.name === name);
  
    if (user && bcrypt.compareSync(password, user.password)) {
      const token = jwt.sign({ name: user.name, role: user.role }, JWT_SECRET, { expiresIn: "1h" });
      return res.json({ token });
    }
  
    // If no match found, return invalid credentials
    res.status(401).json({ message: "Invalid credentials" });
  });



/////////FEATURE: ADMIN CHANGE PASS WORD//////////////
app.put("/change-admin-password", authenticateJWT, authorizeRoles("Admin"), (req, res) => {
    const { oldPassword, newPassword } = req.body;

    // Verify the current password
    if (oldPassword !== process.env.ADMIN_PASSWORD) {
        return res.status(401).json({ success: false, message: "Incorrect current password." });
    }

    // Validate new password (basic check)
    if (!newPassword || newPassword.length < 6) {
        return res.status(400).json({ success: false, message: "New password must be at least 6 characters long." });
    }

    // Update the password in the `.env` file
    const envPath = path.join(__dirname, ".env");
    const newEnvContent = `ADMIN_NAME=${process.env.ADMIN_NAME}\nADMIN_PASSWORD=${newPassword}`;
    fs.writeFileSync(envPath, newEnvContent, "utf-8");

    // Reload environment variables
    require("dotenv").config();

    res.json({ success: true, message: "Admin password updated successfully." });
});
//////////////////////////////////////////////////////
// ===================================================
// FEATURE: SCHEDULING
// ===================================================

// 1. Double-Booking Prevention, Override Scheduling & Conflict Handling
app.put("/update-schedule", authenticateJWT, (req, res) => {
  const { therapistName, timeSlot, day, childName, override } = req.body;
  if (!therapistName || !timeSlot || !day) {
    return res.status(400).json({ success: false, message: "Therapist name, time slot, and day are required." });
  }
  const schedules = readJSONFile(jsonFiles.schedules);
  if (!schedules[therapistName]) {
    return res.status(404).json({ success: false, message: "Therapist schedule not found." });
  }
  if (!schedules[therapistName][timeSlot]) {
    return res.status(400).json({ success: false, message: "Invalid time slot." });
  }
  if (!days.includes(day)) {
    return res.status(400).json({ success: false, message: "Invalid day." });
  }
  // If slot is already booked and no override flag is set, warn (double-booking prevention)
  if (schedules[therapistName][timeSlot][day] && schedules[therapistName][timeSlot][day] !== "" && !override) {
    return res.status(409).json({
      success: false,
      message: "Conflict: Slot already booked. Set override=true to force update." // Conflict Handling stub
    });
  }
  schedules[therapistName][timeSlot][day] = childName || "";
  writeJSONFile(jsonFiles.schedules, schedules);
  logAudit(`Schedule updated for ${therapistName} at ${timeSlot} ${day} by ${req.user.name}`);
  res.status(200).json({ success: true, message: "Schedule updated successfully." });
});

// ==============================
// 1. Schedule Logging & History
// ==============================

function logScheduleChange(changeEntry) {
    const historyPath = path.join(__dirname, "data", "schedule_history.json");
    let history = [];
    if (fs.existsSync(historyPath)) {
      try {
        history = JSON.parse(fs.readFileSync(historyPath, "utf-8"));
      } catch (e) {
        console.error("Error reading schedule history:", e);
      }
    }
    history.push({
      timestamp: new Date().toISOString(),
      change: changeEntry
    });
    fs.writeFileSync(historyPath, JSON.stringify(history, null, 2), "utf-8");
  }
  
  app.get("/schedule/history", authenticateJWT, authorizeRoles("Admin", "Secretary"), (req, res) => {
    const historyPath = path.join(__dirname, "data", "schedule_history.json");
    if (!fs.existsSync(historyPath)) {
      return res.status(404).json({ success: false, message: "No schedule history found." });
    }
    const history = JSON.parse(fs.readFileSync(historyPath, "utf-8"));
    res.json({ success: true, history });
  });
// ===================================================
// FEATURE: ROOMS
// ===================================================

// 1. Maximum Capacity Enforcement & Room Assignment Fixes
app.put("/assign-room", authenticateJWT, authorizeRoles("Admin"), (req, res) => {
  const { therapistName, roomName } = req.body;
  const rooms = readJSONFile(jsonFiles.rooms);
  if (!rooms[roomName]) {
    return res.status(404).json({ success: false, message: "Room not found." });
  }
  // Check therapist workload: Count how many rooms the therapist is already assigned to.
  let assignmentCount = 0;
  for (const room in rooms) {
    if (rooms[room].assignedTherapists.includes(therapistName)) {
      assignmentCount++;
    }
  }
  if (assignmentCount >= 1) {
    return res.status(400).json({ success: false, message: "Therapist is already assigned to a room." });
  }
  
   // Enforce room maximum capacity
   if (rooms[roomName].assignedTherapists.length >= rooms[roomName].maxCapacity) {
    return res.status(400).json({ success: false, message: "Room is at maximum capacity." });
  }
  
  rooms[roomName].assignedTherapists.push(therapistName);
  writeJSONFile(jsonFiles.rooms, rooms);
  res.status(200).json({ success: true, message: `Therapist ${therapistName} assigned to room ${roomName}.` });

  // (Optional) Check therapist availability (stub logic)
  if (rooms[roomName].assignedTherapists.includes(therapistName)) {
    return res.status(400).json({ success: false, message: "Therapist already assigned to this room." });
  }
  rooms[roomName].assignedTherapists.push(therapistName);
  writeJSONFile(jsonFiles.rooms, rooms);
  res.status(200).json({ success: true, message: `Therapist ${therapistName} assigned to room ${roomName}.` });
});

// Therapist self-assignment to a room (with capacity check)
app.put("/choose-room", authenticateJWT, authorizeRoles("Therapist"), (req, res) => {
  const { therapistName, roomName } = req.body;
  const rooms = readJSONFile(jsonFiles.rooms);
  if (!rooms[roomName]) {
    return res.status(404).json({ success: false, message: "Room not found." });
  }
  if (rooms[roomName].assignedTherapists.length >= rooms[roomName].maxCapacity) {
    return res.status(400).json({ success: false, message: "Room is at maximum capacity." });
  }
  if (!rooms[roomName].assignedTherapists.includes(therapistName)) {
    rooms[roomName].assignedTherapists.push(therapistName);
    writeJSONFile(jsonFiles.rooms, rooms);
  }
  res.status(200).json({ success: true, message: `Therapist ${therapistName} successfully chose room ${roomName}.` });
});

app.post("/add-room", authenticateJWT, authorizeRoles("Admin"), (req, res) => {
    const { roomName, maxCapacity } = req.body;
  
    if (!roomName || !maxCapacity || isNaN(maxCapacity)) {
      return res.status(400).json({ success: false, message: "Room name and valid max capacity are required." });
    }
  
    let rooms = readJSONFile(jsonFiles.rooms);
  
    if (rooms[roomName]) {
      return res.status(400).json({ success: false, message: "Room already exists." });
    }
  
    // Add new room
    rooms[roomName] = {
      maxCapacity: parseInt(maxCapacity, 10),
      assignedTherapists: []
    };
  
    writeJSONFile(jsonFiles.rooms, rooms);
    res.status(201).json({ success: true, message: `Room '${roomName}' added successfully.` });
  });

  app.get("/rooms", authenticateJWT, (req, res) => {
    try {
      const rooms = readJSONFile(jsonFiles.rooms);
      res.status(200).json({ success: true, rooms });
    } catch (error) {
      console.error("Error fetching rooms:", error);
      res.status(500).json({ success: false, message: "Error retrieving rooms." });
    }
  });
 
// ===================================================
// FEATURE: ATTENDANCE
// ===================================================


const PDFDocument = require("pdfkit");

app.get("/attendance/monthly-report/:therapistName", authenticateJWT, (req, res) => {
  try {
    const requestedTherapist = req.params.therapistName;

    // Restrict access: Therapists may only access their own attendance data.
    if (req.user.role === "Therapist" && req.user.name !== requestedTherapist) {
      return res.status(403).json({ 
        success: false, 
        message: "Access forbidden: Therapists can only view their own attendance report." 
      });
    }

    // Accept optional query parameters for month and year; default to current month/year.
    const month = req.query.month ? parseInt(req.query.month, 10) : (new Date()).getMonth() + 1;
    const year = req.query.year ? parseInt(req.query.year, 10) : (new Date()).getFullYear();

    // Read attendance data
    const attendanceData = readJSONFile(jsonFiles.attendance);
    const therapistAttendance = attendanceData[requestedTherapist] || {};

    // Filter attendance records for the specified month and year.
    const filteredDates = Object.keys(therapistAttendance)
      .filter(dateStr => {
        const dateObj = new Date(dateStr);
        return (dateObj.getMonth() + 1 === month) && (dateObj.getFullYear() === year);
      })
      .sort(); // Sort dates chronologically

    // Calculate attendance summary
    let totalSessions = 0, totalPresent = 0, totalAbsent = 0;
    filteredDates.forEach(dateStr => {
      const sessions = therapistAttendance[dateStr];
      Object.values(sessions).forEach(record => {
        totalSessions++;
        record.present ? totalPresent++ : totalAbsent++;
      });
    });

    // ✅ Initialize PDF Document
    const doc = new PDFDocument({ margin: 50 });
    res.setHeader("Content-Disposition", `attachment; filename=${requestedTherapist}_attendance_report_${year}_${month}.pdf`);
    res.setHeader("Content-Type", "application/pdf");
    doc.pipe(res);

    // ✅ Report Header
    doc.fontSize(20).text("Monthly Attendance Report", { align: "center" });
    doc.moveDown();
    doc.fontSize(14).text(`Therapist: ${requestedTherapist}`);
    doc.text(`Month/Year: ${month} / ${year}`);
    doc.moveDown();

    // ✅ Summary Section
    doc.fontSize(12).text(`Total Sessions: ${totalSessions}`);
    doc.text(`Total Present: ${totalPresent}`);
    doc.text(`Total Absent: ${totalAbsent}`);
    doc.moveDown();

    // ✅ Handle case when no data exists
    if (filteredDates.length === 0) {
      doc.fontSize(14).fillColor("red").text("No attendance data available for this period.", { align: "center" });
      doc.end();
      return;
    }

    // ✅ Attendance Chart
    const chartWidth = 300;
    const chartHeight = 20;
    const presentBarWidth = totalSessions ? (totalPresent / totalSessions) * chartWidth : 0;
    const absentBarWidth = totalSessions ? (totalAbsent / totalSessions) * chartWidth : 0;

    doc.fontSize(12).text("Attendance Distribution:");
    doc.fillColor("green").rect(doc.x, doc.y, presentBarWidth, chartHeight).fill();
    doc.fillColor("red").rect(doc.x + presentBarWidth, doc.y - chartHeight, absentBarWidth, chartHeight).fill();
    doc.fillColor("black");
    doc.moveDown().moveDown();

    // ✅ Detailed Attendance Records
    filteredDates.forEach(dateStr => {
      doc.fontSize(12).fillColor("blue").text(`Date: ${dateStr}`, { underline: true });
      const sessions = therapistAttendance[dateStr];

      Object.keys(sessions).forEach(timeSlot => {
        const record = sessions[timeSlot];
        const status = record.present ? "Present" : "Absent";
        doc.fillColor("black").text(`   ${timeSlot}: ${record.childName} - ${status}`);
      });

      doc.moveDown();
    });

    // ✅ Finalize PDF
    doc.end();

  } catch (error) {
    console.error("PDF Generation Error:", error);
    res.status(500).json({ success: false, message: "Error generating report." });
  }
});



// ===================================================
// FEATURE: FILES & DOCUMENTS
// ===================================================

// Encrypted File Names: (Implemented via multer storage above)
// Encrypted Backups (Data Recovery System)
const archiver = require('archiver');

app.get("/backup/export", authenticateJWT, authorizeRoles("Admin"), (req, res) => {
  // Set response headers to download a ZIP file
  res.setHeader('Content-disposition', 'attachment; filename=backup.zip');
  res.setHeader('Content-type', 'application/zip');

  // Create a zip archive with maximum compression
  const archive = archiver('zip', { zlib: { level: 9 } });

  // Handle archive errors
  archive.on('error', (err) => {
    res.status(500).send({ error: err.message });
  });

  // Pipe the archive data to the response
  archive.pipe(res);

  // Add all JSON files to the archive.
  // jsonFiles is assumed to be an object mapping keys to relative paths, e.g.:
  // { users: "data/users.json", schedules: "data/schedules.json", attendance: "data/attendance.json", rooms: "data/rooms.json" }
  Object.values(jsonFiles).forEach(relativeFilePath => {
    const filePath = path.join(__dirname, relativeFilePath);
    // Add file to the archive; the file will be stored under its basename
    archive.file(filePath, { name: path.basename(filePath) });
  });

  // Finalize the archive (i.e. finish the ZIP stream)
  archive.finalize();
});

// Document Encryption for Therapist Files [Needs Fix]
// (Assume document files are stored with encrypted names; additional content encryption may be applied here)

// Download Reports & Assessments [Needs Fix]
app.get("/download/assessment/:therapistName/:fileName", authenticateJWT, (req, res) => {
    const { therapistName, fileName } = req.params;
  
    // Role-based access control:
    // Therapists can only download their own files, while Admins/Secretaries can download any.
    if (req.user.role === "Therapist" && req.user.name !== therapistName) {
      return res.status(403).json({
        success: false,
        message: "Access forbidden: Therapists can only download their own assessments."
      });
    }
  
    // Prevent directory traversal by using only the base name of the file.
    const safeFileName = path.basename(fileName);
  
    // Construct the file path for the requested assessment.
    const filePath = path.join(__dirname, "data", "therapists", therapistName, "Αξιολογήσεις", safeFileName);
  
    // Check if the file exists
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ success: false, message: "File not found." });
    }
  
    // Set appropriate headers for file download.
    res.setHeader("Content-Disposition", `attachment; filename="${safeFileName}"`);
    res.setHeader("Content-Type", "application/octet-stream");
  
    // Send the file to the client.
    res.sendFile(filePath);
  });

// ===================================================
// FEATURE: REAL-TIME UPDATES
// ===================================================

// ---------------------------
// Global Live Updates Storage
// ---------------------------
let liveUpdates = [];

// Helper function to add a live update event
const addLiveUpdate = (updateMessage) => {
  liveUpdates.push({
    message: updateMessage,
    timestamp: Date.now()
  });
  // Optionally limit the size of the updates array (e.g., last 100 events)
  if (liveUpdates.length > 100) {
    liveUpdates.shift();
  }
};

// ---------------------------
// Real-Time Updates – Polling Endpoint
// ---------------------------

app.get("/live-updates", authenticateJWT, (req, res) => {
  // Optional: If needed, you can restrict access by role here.
  // For example, if only Admins and Secretaries should see all updates:
  // if (req.user.role === "Therapist") { ... limit data ... }

  // Accept a query parameter 'since' (timestamp in milliseconds)
  const since = req.query.since ? parseInt(req.query.since, 10) : 0;

  // Filter the liveUpdates array for updates with a timestamp greater than 'since'
  const updates = liveUpdates.filter(update => update.timestamp > since);

  res.status(200).json({
    success: true,
    updates
  });
});

addLiveUpdate(`Therapist ${therapistName} was assigned to room ${roomName}.`);
addLiveUpdate(`Attendance updated for ${therapistName} on ${date} at ${time}.`);
addLiveUpdate(`Schedule updated: ${therapistName} now has a session at ${timeSlot} on ${day}.`);
// ===================================================
// EXISTING ENDPOINTS & OTHER FEATURES (e.g. assessments, documents)
// ===================================================

// (Other endpoints such as uploading assessments, updating therapist folders, assigning specialty, uploading templates, etc., remain similar to your original code.)

// For example: Upload Assessment (already implemented)
app.post("/upload-assessment", uploadAssessment.single("file"), (req, res) => {
  const { therapistName } = req.body;
  if (!req.file || !therapistName) {
    return res.status(400).json({ success: false, message: "Therapist name and file are required." });
  }
  console.log(`✅ Assessment uploaded for ${therapistName}: ${req.file.originalname}`);
  res.status(200).json({ success: true, message: "Assessment uploaded successfully." });
});

// ---------------------------
// Therapist Addition Endpoint
// ---------------------------
app.post("/add-therapist", (req, res) => {
  const { adminRole, name, password } = req.body;
  if (!name || !password || !adminRole) {
    return res.status(400).json({ success: false, message: "Όνομα, κωδικός και ρόλος απαιτούνται." });
  }
  // Only Admin or Secretary allowed to add therapist
  if (adminRole !== "Admin" && adminRole !== "Secretary") {
    return res.status(403).json({ success: false, message: "Δεν έχετε άδεια να προσθέσετε θεραπευτές." });
  }
  const users = readJSONFile(jsonFiles.users);
  if (users.find(u => u.name === name)) {
    return res.status(400).json({ success: false, message: "Ο θεραπευτής υπάρχει ήδη." });
  }
  const hashedPassword = bcrypt.hashSync(password, 10);
  const newUser = { id: users.length + 1, name, password: hashedPassword, role: "Therapist" };
  users.push(newUser);
  writeJSONFile(jsonFiles.users, users);
  console.log(`✅ Therapist ${name} added.`);
  // Initialize therapist data
  initializeTherapistSchedule(name);
  initializeTherapistAttendance(name);
  createTherapistFolders(name);
  res.status(201).json({ success: true, message: "Θεραπευτής προστέθηκε και όλα τα δεδομένα δημιουργήθηκαν." });
});


// ==============================
// 3. Notifications for Schedule Changes
// ==============================

let notifications = [];
function addNotification(notification) {
  notifications.push({
    message: notification,
    timestamp: Date.now()
  });
  // Limit to last 100 notifications.
  if (notifications.length > 100) notifications.shift();
}

app.get("/notifications", authenticateJWT, (req, res) => {
  res.json({ success: true, notifications });
});

// (Call addNotification("...") in endpoints where schedule changes occur.)

// ==============================
// 4. File Download Logging
// ==============================

function logFileDownload(therapistName, fileName, userName) {
  const logPath = path.join(__dirname, "data", "file_downloads.log");
  const entry = `[${new Date().toISOString()}] User ${userName} downloaded file ${fileName} for therapist ${therapistName}\n`;
  fs.appendFileSync(logPath, entry, "utf-8");
}

// (The download endpoint below will call logFileDownload)

// ==============================
// 5. Therapist Login Activity Logs
// ==============================

function logLoginActivity(userName) {
  const logPath = path.join(__dirname, "data", "login_activity.log");
  const entry = `[${new Date().toISOString()}] Therapist ${userName} logged in\n`;
  fs.appendFileSync(logPath, entry, "utf-8");
}

// (Call logLoginActivity(user.name) in your /login endpoint after successful authentication.)

// ==============================
// 6. Password Reset System
// ==============================

let passwordResetTokens = {}; // In-memory storage; in production, use a persistent store.

app.post("/password-reset-request", (req, res) => {
  const { therapistName } = req.body;
  const users = readJSONFile(jsonFiles.users);
  const user = users.find(u => u.name === therapistName);
  if (!user) {
    return res.status(404).json({ success: false, message: "Therapist not found." });
  }
  const token = crypto.randomBytes(20).toString("hex");
  passwordResetTokens[therapistName] = { token, expires: Date.now() + 3600000 }; // 1 hour expiry.
  console.log(`Password reset token for ${therapistName}: ${token}`);
  res.json({ success: true, message: "Password reset token generated. Check your email." });
});

app.post("/password-reset", (req, res) => {
  const { therapistName, token, newPassword } = req.body;
  if (!therapistName || !token || !newPassword) {
    return res.status(400).json({ success: false, message: "Missing required fields." });
  }
  const record = passwordResetTokens[therapistName];
  if (!record || record.token !== token || Date.now() > record.expires) {
    return res.status(400).json({ success: false, message: "Invalid or expired token." });
  }
  let users = readJSONFile(jsonFiles.users);
  const userIndex = users.findIndex(u => u.name === therapistName);
  if (userIndex === -1) {
    return res.status(404).json({ success: false, message: "Therapist not found." });
  }
  users[userIndex].password = bcrypt.hashSync(newPassword, 10);
  writeJSONFile(jsonFiles.users, users);
  delete passwordResetTokens[therapistName];
  res.json({ success: true, message: "Password reset successfully." });
});

// ==============================
// 7. Room Assignment API (Fix)
// ==============================

function isTherapistAvailable(therapistName) {
  // Stub: In production, check the therapist's current schedule/room assignments.
  return true;
}

app.put("/assign-room", authenticateJWT, authorizeRoles("Admin"), (req, res) => {
  const { therapistName, roomName } = req.body;
  const rooms = readJSONFile(jsonFiles.rooms);
  if (!rooms[roomName]) {
    return res.status(404).json({ success: false, message: "Room not found." });
  }
  if (!isTherapistAvailable(therapistName)) {
    return res.status(400).json({ success: false, message: "Therapist is not available for room assignment." });
  }
  if (rooms[roomName].assignedTherapists.length >= rooms[roomName].maxCapacity) {
    return res.status(400).json({ success: false, message: "Room is at maximum capacity." });
  }
  if (rooms[roomName].assignedTherapists.includes(therapistName)) {
    return res.status(400).json({ success: false, message: "Therapist already assigned to this room." });
  }
  rooms[roomName].assignedTherapists.push(therapistName);
  writeJSONFile(jsonFiles.rooms, rooms);
  res.status(200).json({ success: true, message: `Therapist ${therapistName} assigned to room ${roomName}.` });
});

// ===================================================
// FEATURE: DOUBLE-BOOKING PREVENTION IN SCHEDULING (Fix)
// ===================================================

app.put("/update-schedule", authenticateJWT, (req, res) => {
    const { therapistName, timeSlot, day, childName, override } = req.body;
    // Extract the confirmation flag from the query parameters
    const confirmOverride = req.query.confirm === 'true';
  
    if (!therapistName || !timeSlot || !day) {
      return res.status(400).json({ success: false, message: "Therapist name, time slot, and day are required." });
    }
  
    const schedules = readJSONFile(jsonFiles.schedules);
    if (!schedules[therapistName]) {
      return res.status(404).json({ success: false, message: "Therapist schedule not found." });
    }
    if (!schedules[therapistName][timeSlot]) {
      return res.status(400).json({ success: false, message: "Invalid time slot." });
    }
    if (!days.includes(day)) {
      return res.status(400).json({ success: false, message: "Invalid day." });
    }
  
    // Only Admins can force an override.
    // If the override flag is set and the user is an Admin, they must include confirm=true in the query string.
    if (override && req.user.role === "Admin" && !confirmOverride) {
      return res.status(400).json({
        success: false,
        message: "Override flag is set. Please confirm override by including confirm=true in the query parameters."
      });
    }
  
    // If the slot is already booked and no override flag is set, return a conflict error.
    if (schedules[therapistName][timeSlot][day] && schedules[therapistName][timeSlot][day] !== "" && !override) {
      return res.status(409).json({ success: false, message: "Conflict: Slot already booked." });
    }
  
    // Update the schedule
    schedules[therapistName][timeSlot][day] = childName || "";
    writeJSONFile(jsonFiles.schedules, schedules);
  
    // Log the change
    logAudit(`Schedule updated for ${therapistName} at ${timeSlot} ${day} by ${req.user.name}`);
    logScheduleChange(`Schedule updated for ${therapistName} at ${timeSlot} ${day} by ${req.user.name}`);
  
    return res.status(200).json({ success: true, message: "Schedule updated successfully." });
  });

// ==============================
// 9. Therapist Deletion (Fix)
// ==============================

app.delete("/delete-therapist", authenticateJWT, authorizeRoles("Admin"), (req, res) => {
  const { therapistName } = req.body;
  if (!therapistName) {
    return res.status(400).json({ success: false, message: "Therapist name is required." });
  }
  let users = readJSONFile(jsonFiles.users);
  const userIndex = users.findIndex(u => u.name === therapistName);
  if (userIndex === -1) {
    return res.status(404).json({ success: false, message: "Therapist not found." });
  }
  users.splice(userIndex, 1);
  writeJSONFile(jsonFiles.users, users);
  
  let schedules = readJSONFile(jsonFiles.schedules);
  delete schedules[therapistName];
  writeJSONFile(jsonFiles.schedules, schedules);
  
  let attendance = readJSONFile(jsonFiles.attendance);
  delete attendance[therapistName];
  writeJSONFile(jsonFiles.attendance, attendance);
  
  const therapistFolder = path.join(__dirname, "data", "therapists", therapistName);
  if (fs.existsSync(therapistFolder)) {
    fs.rmdirSync(therapistFolder, { recursive: true });
  }
  logAudit(`Therapist ${therapistName} was deleted by ${req.user.name}`);
  res.status(200).json({ success: true, message: "Therapist deleted successfully." });
});

// ==============================
// 10. Attendance Editing by Admins (Fix)
// ==============================

app.put("/attendance/edit", authenticateJWT, authorizeRoles("Admin"), (req, res) => {
  const { therapistName, date, time, childName, present } = req.body;
  if (!therapistName || !date || !time || !childName || present === undefined) {
    return res.status(400).json({ success: false, message: "Missing required fields: therapistName, date, time, childName, present." });
  }
  const parsedDate = new Date(date);
  if (isNaN(parsedDate.getTime())) {
    return res.status(400).json({ success: false, message: "Invalid date format." });
  }
  if (!timeSlots.includes(time)) {
    return res.status(400).json({ success: false, message: `Invalid time slot. Allowed: ${timeSlots.join(", ")}` });
  }
  if (typeof childName !== "string" || childName.trim() === "") {
    return res.status(400).json({ success: false, message: "Child name must be a non-empty string." });
  }
  const isPresent = (present === true || present === "true" || present === 1 || present === "1");
  const attendance = readJSONFile(jsonFiles.attendance);
  if (!attendance[therapistName]) {
    return res.status(404).json({ success: false, message: "Attendance record not found for this therapist." });
  }
  const oldRecord =
    attendance[therapistName][date] && attendance[therapistName][date][time]
      ? attendance[therapistName][date][time]
      : null;
  if (!attendance[therapistName][date]) {
    attendance[therapistName][date] = {};
  }
  attendance[therapistName][date][time] = { childName: childName.trim(), present: isPresent };
  writeJSONFile(jsonFiles.attendance, attendance);
  logAudit(`Admin ${req.user.name} edited attendance for ${therapistName} on ${date} at ${time}. Old record: ${JSON.stringify(oldRecord)}, New record: ${JSON.stringify(attendance[therapistName][date][time])}`);
  res.status(200).json({ success: true, message: "Attendance updated successfully." });
});

// Therapist Role Management: Update a therapist's role
app.put("/update-therapist-role", authenticateJWT, authorizeRoles("Admin"), (req, res) => {
    const { therapistName, newRole } = req.body;
    if (!therapistName || !newRole) {
      return res.status(400).json({ success: false, message: "Therapist name and new role are required." });
    }
    
    let users = readJSONFile(jsonFiles.users);
    const userIndex = users.findIndex(u => u.name === therapistName);
    if (userIndex === -1) {
      return res.status(404).json({ success: false, message: "Therapist not found." });
    }
    
    users[userIndex].role = newRole;
    writeJSONFile(jsonFiles.users, users);
    logAudit(`Admin ${req.user.name} updated role for ${therapistName} to ${newRole}`);
    
    res.status(200).json({ success: true, message: `Therapist role updated to ${newRole}` });
  });
///////////test api///////////
app.post("/test-live-update", authenticateJWT, (req, res) => {
    const { message } = req.body;
    if (!message) {
      return res.status(400).json({ success: false, message: "Message is required." });
    }
    addLiveUpdate(message);
    res.json({ success: true, message: "Test update added successfully." });
  });
//////////////////////////////

// ==============================
// Secretery role 
// ==============================
app.post("/admin/add-secretary", authenticateJWT, authorizeRoles("Admin"), (req, res) => {
    const { name, password } = req.body;

    if (!name || !password) {
        return res.status(400).json({ success: false, message: "Όνομα και κωδικός απαιτούνται." });
    }

    let users = readJSONFile(jsonFiles.users);

    if (users.find(u => u.name === name)) {
        return res.status(400).json({ success: false, message: "Ο χρήστης υπάρχει ήδη." });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);
    const newUser = { id: users.length + 1, name, password: hashedPassword, role: "Secretary" };
    users.push(newUser);

    writeJSONFile(jsonFiles.users, users);
    console.log(`✅ Admin added Secretary: ${name}`);

    res.status(201).json({ success: true, message: "Γραμματέας προστέθηκε επιτυχώς από τον διαχειριστή." });
});

app.put("/admin/update-role", authenticateJWT, authorizeRoles("Admin"), (req, res) => {
    const { name, newRole } = req.body;

    if (!name || !newRole) {
        return res.status(400).json({ success: false, message: "Όνομα χρήστη και νέο ρόλο απαιτούνται." });
    }
    if (!["Admin", "Secretary", "Therapist"].includes(newRole)) {
        return res.status(400).json({ success: false, message: "Μη έγκυρος ρόλος. Επιτρεπτοί ρόλοι: Admin, Secretary, Therapist." });
    }

    let users = readJSONFile(jsonFiles.users);
    const userIndex = users.findIndex(u => u.name === name);
    if (userIndex === -1) {
        return res.status(404).json({ success: false, message: "Ο χρήστης δεν βρέθηκε." });
    }

    users[userIndex].role = newRole;
    writeJSONFile(jsonFiles.users, users);
    logAudit(`Admin ${req.user.name} updated role for ${name} to ${newRole}`);

    res.status(200).json({ success: true, message: `Ο ρόλος του χρήστη ενημερώθηκε σε ${newRole}` });
});

app.post("/secretary/add-therapist", authenticateJWT, authorizeRoles("Secretary"), (req, res) => {
    const { name, password } = req.body;

    if (!name || !password) {
        return res.status(400).json({ success: false, message: "Όνομα και κωδικός απαιτούνται." });
    }

    let users = readJSONFile(jsonFiles.users);

    if (users.find(u => u.name === name)) {
        return res.status(400).json({ success: false, message: "Ο θεραπευτής υπάρχει ήδη." });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);
    const newUser = { id: users.length + 1, name, password: hashedPassword, role: "Therapist" };
    users.push(newUser);

    writeJSONFile(jsonFiles.users, users);
    console.log(`✅ Secretary added therapist: ${name}`);

    // Initialize therapist data
    initializeTherapistSchedule(name);
    initializeTherapistAttendance(name);
    createTherapistFolders(name);

    res.status(201).json({ success: true, message: "Θεραπευτής προστέθηκε από γραμματέα." });
});
app.put("/secretary/update-schedule", authenticateJWT, authorizeRoles("Secretary"), (req, res) => {
    const { therapistName, timeSlot, day, childName, override } = req.body;

    if (!therapistName || !timeSlot || !day) {
        return res.status(400).json({ success: false, message: "Therapist name, time slot, and day are required." });
    }

    const schedules = readJSONFile(jsonFiles.schedules);
    if (!schedules[therapistName]) {
        return res.status(404).json({ success: false, message: "Therapist schedule not found." });
    }
    if (!schedules[therapistName][timeSlot]) {
        return res.status(400).json({ success: false, message: "Invalid time slot." });
    }
    if (!days.includes(day)) {
        return res.status(400).json({ success: false, message: "Invalid day." });
    }

    // Double booking prevention unless override is set
    if (schedules[therapistName][timeSlot][day] && schedules[therapistName][timeSlot][day] !== "" && !override) {
        return res.status(409).json({
            success: false,
            message: "Conflict: Slot already booked. Set override=true to force update."
        });
    }

    schedules[therapistName][timeSlot][day] = childName || "";
    writeJSONFile(jsonFiles.schedules, schedules);

    logAudit(`Secretary updated schedule for ${therapistName} at ${timeSlot} on ${day}`);

    res.status(200).json({ success: true, message: "Schedule updated successfully." });
});
app.get("/secretary/attendance-summary", authenticateJWT, authorizeRoles("Secretary"), (req, res) => {
    const attendanceData = readJSONFile(jsonFiles.attendance);
    let summary = {};

    const aggregateAttendance = (data) => {
        let totalSessions = 0, totalPresent = 0, totalAbsent = 0;
        Object.keys(data).forEach(date => {
            const sessions = data[date];
            Object.keys(sessions).forEach(timeSlot => {
                totalSessions++;
                if (sessions[timeSlot].present) {
                    totalPresent++;
                } else {
                    totalAbsent++;
                }
            });
        });

        return {
            totalSessions,
            totalPresent,
            totalAbsent,
            percentagePresent: totalSessions > 0 ? ((totalPresent / totalSessions) * 100).toFixed(2) : "0.00"
        };
    };

    Object.keys(attendanceData).forEach(therapistName => {
        summary[therapistName] = aggregateAttendance(attendanceData[therapistName]);
    });

    res.status(200).json({ success: true, summary });
});

// ---------------------------
// Starting the Server
// ---------------------------
const configPath = path.join(__dirname, "config", "serverConfig.json");
const getConfig = () => {
  try {
    return JSON.parse(fs.readFileSync(configPath, "utf-8"));
  } catch (error) {
    console.error("❌ Error loading config file. Using default settings.");
    return { host: "localhost", port: 4000 };
  }
};

const { host, port } = getConfig();
app.listen(port, host, () => {
  console.log(`🚀 Server running at http://${host}:${port}`);
}).on("error", (err) => {
  console.error(`❌ Failed to start server: ${err.message}`);
});

module.exports = {
  encryptFile,
  decryptFile,
  readJSONFile,
  writeJSONFile,
  initializeTherapistSchedule
};