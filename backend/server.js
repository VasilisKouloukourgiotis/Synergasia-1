require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const multer = require("multer");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const ALGORITHM = "aes-256-cbc";
const SALT = process.env.SALT
const SECRET_KEY = process.env.SECRET_KEY;

const app = express();
app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(bodyParser.json());
app.use(express.json()); // ✅ Ensures JSON parsing

const jsonFiles = {
  users: "data/users.json",
  schedules: "data/schedules.json",
  attendance: "data/attendance.json",
  rooms: "data/rooms.json" // ✅ Add room assignments
};


//////////////////////////////////jason files/////////////////////////////////

const dataDir = path.join(__dirname, "data"); // Main data folder
const usersPath = path.join(dataDir, "users.json");
const schedulesPath = path.join(dataDir, "schedules.json");
const attendancePath = path.join(dataDir, "attendance.json");
const roomsPath = path.join(dataDir, "rooms.json");


// 📌 Default Structures for Each File
const defaultData = {
  users: [],
  schedules: {},
  attendance: {},
  rooms: {}
};

// 📌 Ensure JSON file exists or create it with default content
const ensureFileExists = (filePath, defaultContent) => {
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, JSON.stringify(defaultContent, null, 2), "utf-8");
    console.log(`🆕 Created missing file: ${filePath}`);
  }
};

// 📌 Ensure All JSON Files Exist
const ensureAllJSONFiles = () => {
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
    console.log("📁 Created missing data directory");
  }

  ensureFileExists(usersPath, defaultData.users);
  ensureFileExists(schedulesPath, defaultData.schedules);
  ensureFileExists(attendancePath, defaultData.attendance);
  ensureFileExists(roomsPath, defaultData.rooms);

  console.log("✅ All required JSON files are verified.");
};

ensureFileExists(roomsPath, {});
ensureFileExists(jsonFiles.schedules, {});
// Run the function at startup (DO NOT redeclare it again elsewhere)
ensureAllJSONFiles();



//////////////////////////////////////////////////////////////////////////////


// Load server configuration (host & port)
const configPath = path.join(__dirname, "config", "serverConfig.json");
const getConfig = () => {
  try {
    return JSON.parse(fs.readFileSync(configPath, "utf-8"));
  } catch (error) {
    console.error("❌ Error loading config file. Using default settings.");
    return { host: "localhost", port: 4000 }; // ✅ Default values if config file fails
  }
};

const { host, port } = getConfig();
console.log(`🚀 Server running at http://${host}:${port}`);
// Helper Functions
/////////////////////////////encryption/////////////////////////////////////////////////////


// 🔒 Encrypt file content
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

// 🔓 Decrypt file content
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



////////////////////////////////////////Automatically Encrypt JSON Files////////////////////////////////////////////////////

// Read JSON File with Automatic Decryption

const readJSONFile = (filePath) => {
  try {
    const absolutePath = path.join(__dirname, filePath);
    if (!fs.existsSync(absolutePath)) {
      console.log(`⚠️ File ${filePath} does not exist.`);
      return {};
    }

    decryptFile(absolutePath, SECRET_KEY);
    const fileData = fs.readFileSync(absolutePath, "utf-8");
    const jsonData = JSON.parse(fileData);
    return JSON.parse(fileData);
  } catch (error) {
    console.error(`❌ Error reading JSON file (${filePath}):`, error);
    return {}; // ✅ Ensure function does not break
  }
};



// Write JSON File with Automatic Encryption
const writeJSONFile = (filePath, data) => {
  try {
      const absolutePath = path.join(__dirname, filePath);
      fs.writeFileSync(absolutePath, JSON.stringify(data, null, 2), "utf-8");
      
      // Encrypt the file after writing
      encryptFile(absolutePath, SECRET_KEY);

      console.log(`✅ JSON file saved and encrypted: ${filePath}`);
  } catch (error) {
      console.error(`❌ Failed to write JSON file: ${filePath}, Error:`, error);
  }
};




////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


// Ensure directory exists
const ensureDirectoryExists = (dirPath) => {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
    console.log(`📁 Created missing directory: ${dirPath}`);
  }
};



//////////////////////////////// DOCUMENTATION ///////////////////////////////////////////

// Create therapist folder structure
const createTherapistFolder = (therapistName) => {
  const basePath = path.join(__dirname, "data", "therapists", therapistName);
  ensureDirectoryExists(basePath);
  ensureDirectoryExists(path.join(basePath, "Αναφορές"));
  ensureDirectoryExists(path.join(basePath, "Child_Docs"));
  ensureDirectoryExists(path.join(basePath, "Weekly_Docs"));
  ensureDirectoryExists(path.join(basePath, "Αξιολογήσεις")); // New Assessments Folder
};

// 📌 Upload Admin's Assessment for Therapist
const storageAssessments = multer.diskStorage({
  destination: (req, file, cb) => {
    const { therapistName } = req.body;
    const assessmentsPath = path.join(__dirname, "data", "therapists", therapistName, "Αξιολογήσεις");
    ensureDirectoryExists(assessmentsPath);
    cb(null, assessmentsPath);
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname);
  },
});
const uploadAssessment = multer({ storage: storageAssessments });

app.post("/upload-assessment", uploadAssessment.single("file"), (req, res) => {
  const { therapistName } = req.body;

  if (!req.file || !therapistName) {
    return res.status(400).json({ success: false, message: "Therapist name and file are required." });
  }

  console.log(`✅ Assessment uploaded for ${therapistName}: ${req.file.originalname}`);
  res.status(200).json({ success: true, message: "Assessment uploaded successfully." });
});

// 📌 List All Assessments for a Therapist
app.get("/list-assessments/:therapistName", (req, res) => {
  const therapistName = req.params.therapistName;
  const assessmentsPath = path.join(__dirname, "data", "therapists", therapistName, "Αξιολογήσεις");

  if (!fs.existsSync(assessmentsPath)) {
    return res.status(404).json({ success: false, message: "No assessments found for this therapist." });
  }

  const files = fs.readdirSync(assessmentsPath);
  res.json({ success: true, files });
});

// 📌 Delete an Assessment
app.delete("/delete-assessment", (req, res) => {
  const { therapistName, fileName } = req.body;

  const filePath = path.join(__dirname, "data", "therapists", therapistName, "Αξιολογήσεις", fileName);

  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ success: false, message: "File not found." });
  }

  fs.unlinkSync(filePath);
  console.log(`🗑️ Deleted assessment: ${fileName} for ${therapistName}`);
  res.status(200).json({ success: true, message: "Assessment deleted successfully." });
});


// Update therapist folder if the Admin changes the therapist’s name
app.put("/update-therapist-name", (req, res) => {
  const { oldName, newName } = req.body;
  const oldPath = path.join(__dirname, "data", "therapists", oldName);
  const newPath = path.join(__dirname, "data", "therapists", newName);

  if (!fs.existsSync(oldPath)) return res.status(404).json({ success: false, message: "Therapist folder not found." });

  fs.renameSync(oldPath, newPath);
  res.status(200).json({ success: true, message: "Therapist folder updated successfully." });
});

// Assign Specialty to a Therapist
app.put("/assign-specialty", (req, res) => {
  const { therapistName, specialty } = req.body;
  const users = readJSONFile("users.json");
  const therapist = users.find((u) => u.name === therapistName && u.role === "Therapist");

  if (!therapist) return res.status(404).json({ success: false, message: "Therapist not found." });

  therapist.specialty = specialty;
  writeJSONFile("users.json", users);
  res.status(200).json({ success: true, message: "Specialty assigned successfully." });
});

// Get the correct documentation template for a therapist
app.get("/get-template/:therapistName", (req, res) => {
  const therapistName = req.params.therapistName;
  const users = readJSONFile("users.json");
  const therapist = users.find((u) => u.name === therapistName);

  if (!therapist) {
    console.log(`❌ Therapist '${therapistName}' not found.`);
    return res.status(404).json({ success: false, message: "Therapist not found." });
  }

  if (!therapist.specialty) {
    console.log(`⚠️ Therapist '${therapistName}' has no assigned specialty.`);
    return res.status(400).json({ success: false, message: "Specialty not assigned." });
  }

  const specialty = therapist.specialty.replace(/\s/g, "_"); // Replace spaces with underscores
  const templatePath = path.join(__dirname, "data", "templates", `${specialty}.docx`);
  const customTemplatePath = path.join(__dirname, "data", "templates", "Custom_Templates", `${therapistName}_Custom.docx`);

  console.log(`🔍 Checking for Custom Template: ${customTemplatePath}`);
  console.log(`🔍 Checking for Default Template: ${templatePath}`);

  if (fs.existsSync(customTemplatePath)) {
    console.log(`✅ Custom template found for ${therapistName}`);
    return res.sendFile(customTemplatePath);
  }

  if (fs.existsSync(templatePath)) {
    console.log(`✅ Default template found for ${specialty}`);
    return res.sendFile(templatePath);
  }

  console.log(`❌ No template found for ${therapistName} (${specialty})`);
  res.status(404).json({ success: false, message: "Template not found." });
});

// Upload Custom Template for a Therapist
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, "data", "templates", "Custom_Templates");
    ensureDirectoryExists(uploadPath);
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    cb(null, `${req.body.therapistName}_Custom.docx`);
  },
});
const upload = multer({ storage });

app.post("/upload-template", upload.single("template"), (req, res) => {
  if (!req.file || !req.body.therapistName) return res.status(400).json({ success: false, message: "File and therapist name are required." });

  res.status(200).json({ success: true, message: "Custom template uploaded successfully." });
});

// Toggle Weekly vs. Child-Based Documentation
app.put("/update-doc-preference", (req, res) => {
  const { therapistName, preference } = req.body;
  const users = readJSONFile("users.json");
  const therapist = users.find((u) => u.name === therapistName);

  if (!therapist) return res.status(404).json({ success: false, message: "Therapist not found." });

  therapist.preference = preference; // "weekly" or "child-based"
  writeJSONFile("users.json", users);
  res.status(200).json({ success: true, message: "Preference updated successfully." });
});

// Upload Therapist Documentation
app.post("/upload-document", upload.single("file"), (req, res) => {
  const { therapistName, childName } = req.body;

  if (!req.file) {
    return res.status(400).json({ success: false, message: "No file uploaded." });
  }

  const users = readJSONFile("users.json");
  const therapist = users.find((u) => u.name === therapistName);

  if (!therapist) {
    return res.status(404).json({ success: false, message: "Therapist not found." });
  }

  // Determine the save path based on therapist preference
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

  // Move file to correct directory
  const filePath = path.join(savePath, req.file.originalname);
  fs.renameSync(req.file.path, filePath);

  console.log(`✅ File uploaded: ${filePath}`);
  res.status(200).json({ success: true, message: "File uploaded successfully." });
});

// 🔥 NEW FEATURE: List Therapist Documentation
app.get("/list-documents/:therapistName", (req, res) => {
  const therapistName = req.params.therapistName;
  const users = readJSONFile("users.json");
  const therapist = users.find((u) => u.name === therapistName);

  if (!therapist) {
    return res.status(404).json({ success: false, message: "Therapist not found." });
  }

  const weeklyDocsPath = path.join(__dirname, "data", "therapists", therapistName, "Weekly_Docs");
  const childDocsPath = path.join(__dirname, "data", "therapists", therapistName, "Child_Docs");

  let weeklyFiles = fs.existsSync(weeklyDocsPath) ? fs.readdirSync(weeklyDocsPath) : [];
  let childFolders = fs.existsSync(childDocsPath) ? fs.readdirSync(childDocsPath) : [];

  let childDocs = {};
  childFolders.forEach((child) => {
    const childPath = path.join(childDocsPath, child);
    if (fs.statSync(childPath).isDirectory()) {
      childDocs[child] = fs.readdirSync(childPath);
    }
  });

  res.json({ success: true, weeklyFiles, childDocs });
});

// 🔥 NEW FEATURE: Delete a Therapist’s Document
app.delete("/delete-document", (req, res) => {
  const { therapistName, fileName, childName } = req.body;

  const users = readJSONFile("users.json");
  const therapist = users.find((u) => u.name === therapistName);

  if (!therapist) {
    return res.status(404).json({ success: false, message: "Therapist not found." });
  }

  let filePath;
  if (therapist.preference === "weekly") {
    filePath = path.join(__dirname, "data", "therapists", therapistName, "Weekly_Docs", fileName);
  } else {
    if (!childName) {
      return res.status(400).json({ success: false, message: "Child name is required for child-based documentation." });
    }
    filePath = path.join(__dirname, "data", "therapists", therapistName, "Child_Docs", childName, fileName);
  }

  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ success: false, message: "File not found." });
  }

  fs.unlinkSync(filePath);
  res.status(200).json({ success: true, message: "Document deleted successfully." });
});

// 🔥 NEW FEATURE: Admin View All Therapist Documentation
app.get("/admin/view-all-docs", (req, res) => {
  const therapistFoldersPath = path.join(__dirname, "data", "therapists");
  if (!fs.existsSync(therapistFoldersPath)) {
    return res.status(404).json({ success: false, message: "No therapist data found." });
  }

  let therapistDocs = {};
  const therapists = fs.readdirSync(therapistFoldersPath);

  therapists.forEach((therapist) => {
    const weeklyDocsPath = path.join(therapistFoldersPath, therapist, "Weekly_Docs");
    const childDocsPath = path.join(therapistFoldersPath, therapist, "Child_Docs");

    let weeklyFiles = fs.existsSync(weeklyDocsPath) ? fs.readdirSync(weeklyDocsPath) : [];
    let childFolders = fs.existsSync(childDocsPath) ? fs.readdirSync(childDocsPath) : [];

    let childDocs = {};
    childFolders.forEach((child) => {
      const childPath = path.join(childDocsPath, child);
      if (fs.statSync(childPath).isDirectory()) {
        childDocs[child] = fs.readdirSync(childPath);
      }
    });

    therapistDocs[therapist] = { weeklyFiles, childDocs };
  });

  res.json({ success: true, therapistDocs });
});

// 🔥 NEW FEATURE: Admin Move Document Between Therapists
app.put("/admin/move-document", (req, res) => {
  const { fromTherapist, toTherapist, fileName, childName } = req.body;

  let sourcePath, destPath;

  if (childName) {
    sourcePath = path.join(__dirname, "data", "therapists", fromTherapist, "Child_Docs", childName, fileName);
    destPath = path.join(__dirname, "data", "therapists", toTherapist, "Child_Docs", childName);
  } else {
    sourcePath = path.join(__dirname, "data", "therapists", fromTherapist, "Weekly_Docs", fileName);
    destPath = path.join(__dirname, "data", "therapists", toTherapist, "Weekly_Docs");
  }

  if (!fs.existsSync(sourcePath)) {
    return res.status(404).json({ success: false, message: "File not found." });
  }

  ensureDirectoryExists(destPath);
  fs.renameSync(sourcePath, path.join(destPath, fileName));

  res.status(200).json({ success: true, message: "Document moved successfully." });
});

// 📌 List All Documents for a Therapist
app.get("/list-documents/:therapistName", (req, res) => {
  const therapistName = req.params.therapistName;
  const basePath = path.join(__dirname, "data", "therapists", therapistName);

  if (!fs.existsSync(basePath)) {
    return res.status(404).json({ success: false, message: "Therapist folder not found." });
  }

  // Get weekly documents
  const weeklyPath = path.join(basePath, "Weekly_Docs");
  const weeklyFiles = fs.existsSync(weeklyPath) ? fs.readdirSync(weeklyPath) : [];

  // Get child-based documents
  const childPath = path.join(basePath, "Child_Docs");
  let childDocs = {};
  if (fs.existsSync(childPath)) {
    const childFolders = fs.readdirSync(childPath);
    childFolders.forEach((child) => {
      const childFolderPath = path.join(childPath, child);
      childDocs[child] = fs.readdirSync(childFolderPath);
    });
  }

  res.json({ success: true, weeklyFiles, childDocs });
});
////////////////////////////////// SCHEDULE ////////////////////////////////////////





// Ensure required files exist
ensureFileExists(schedulesPath, {}, SECRET_KEY);
ensureFileExists(attendancePath, {}, SECRET_KEY);
ensureFileExists(usersPath, [], SECRET_KEY);


// 📌 Read & Write Helper Functions
const readJSON = (filePath, password) => {
  const absolutePath = path.join(__dirname, filePath);
  if (!fs.existsSync(absolutePath)) return {}; // Return empty object if file doesn't exist

  decryptFile(absolutePath, password); // 🔓 Decrypt before reading
  const data = JSON.parse(fs.readFileSync(absolutePath, "utf-8"));

  encryptFile(absolutePath, password); // 🔐 Re-encrypt after reading
  return data;
};

const writeJSON = (filePath, data, password) => {
  const absolutePath = path.join(__dirname, filePath);
  fs.writeFileSync(absolutePath, JSON.stringify(data, null, 2), "utf-8");
  encryptFile(absolutePath, password); // 🔐 Encrypt after writing
};



// 📌 Default Time Slots & Days in Greek
const timeSlots = ["1:15", "2:00", "2:45", "3:45", "4:30", "5:15", "6:00", "6:45", "7:30", "8:15"];
const days = ["Δευτέρα", "Τρίτη", "Τετάρτη", "Πέμπτη", "Παρασκευή"];

// 📌 Create therapist folders
const createTherapistFolders = (therapistName) => {
  const basePath = path.join(__dirname, "data", "therapists", therapistName);

  // Ensure main therapist folder exists
  if (!fs.existsSync(basePath)) {
    fs.mkdirSync(basePath, { recursive: true });
    console.log(`📁 Φάκελος θεραπευτή δημιουργήθηκε: ${therapistName}`);
  }

  // Ensure required subfolders exist
  ["Αναφορές", "Child_Docs", "Weekly_Docs", "Αξιολογήσεις"].forEach((folder) => {
    const folderPath = path.join(basePath, folder);
    if (!fs.existsSync(folderPath)) {
      fs.mkdirSync(folderPath, { recursive: true });
      console.log(`📁 Φάκελος δημιουργήθηκε: ${folderPath}`);
    }
  });
};

// 📌 Initialize therapist schedule
const initializeTherapistSchedule = (therapistName) => {
  const schedules = readJSONFile(jsonFiles.schedules);

  if (!schedules[therapistName]) {
    schedules[therapistName] = {};

    timeSlots.forEach((time) => {
      schedules[therapistName][time] = {
        "Δευτέρα": "", "Τρίτη": "", "Τετάρτη": "", "Πέμπτη": "", "Παρασκευή": ""
      };
    });

    // Save and encrypt schedules.json
    writeJSONFile(jsonFiles.schedules, schedules);
    console.log(`✅ Πρόγραμμα δημιουργήθηκε για τον θεραπευτή: ${therapistName}`);
  }
};


// 📌 Initialize therapist attendance tracking

const initializeTherapistAttendance = (therapistName) => {
  const attendance = readJSON(jsonFiles.attendance, SECRET_KEY);

  if (!attendance[therapistName]) {
    attendance[therapistName] = {}; // Create an empty object for this therapist

    // Save and encrypt attendance.json
    writeJSON(jsonFiles.attendance, attendance, SECRET_KEY);
    console.log(`✅ Παρουσίες δημιουργήθηκαν για τον θεραπευτή: ${therapistName}`);
  }
};

// 📌 Add a new therapist (Only Admin/Secretary)

app.post("/add-therapist", (req, res) => {
  const { adminRole, name, password } = req.body;

  if (!name || !password || !adminRole) {
    return res.status(400).json({ success: false, message: "Όνομα, κωδικός και ρόλος απαιτούνται." });
  }

  // Read existing users
  const users = readJSONFile(jsonFiles.users);

  // Check if user is admin or secretary
  if (adminRole !== "Admin" && adminRole !== "Secretary") {
    return res.status(403).json({ success: false, message: "Δεν έχετε άδεια να προσθέσετε θεραπευτές." });
  }

  // Check if therapist already exists
  if (users.find((u) => u.name === name)) {
    return res.status(400).json({ success: false, message: "Ο θεραπευτής υπάρχει ήδη." });
  }

  // Hash the password for security
  const hashedPassword = bcrypt.hashSync(password, 10);

  // Add therapist to users list
  const newUser = { id: users.length + 1, name, password: hashedPassword, role: "Therapist" };
  users.push(newUser);

  // Save and encrypt users.json
  writeJSONFile(jsonFiles.users, users);
  console.log(`✅ Θεραπευτής ${name} προστέθηκε.`);

  // 🛠️ Initialize therapist data
  initializeTherapistSchedule(name);
  initializeTherapistAttendance(name);
  createTherapistFolders(name);

  res.status(201).json({ success: true, message: "Θεραπευτής προστέθηκε και όλα τα δεδομένα δημιουργήθηκαν." });
});




// 📌 Fetch therapist attendance
app.get("/attendance/:therapistName", (req, res) => {
  const { therapistName } = req.params;
  const attendance = readJSON(attendancePath, SECRET_KEY);

  if (!attendance[therapistName]) {
    return res.status(404).json({ success: false, message: "Παρουσίες θεραπευτή δεν βρέθηκαν." });
  }

  res.status(200).json({ success: true, attendance: attendance[therapistName] });
});

// 📌 Mark attendance for a therapist
app.post("/mark-attendance", (req, res) => {
  const { therapistName, date, time, childName, present } = req.body;
  const attendance = readJSON(attendancePath);

  if (!attendance[therapistName]) {
    return res.status(404).json({ success: false, message: "Παρουσίες θεραπευτή δεν βρέθηκαν." });
  }

  if (!date || !time || !childName || present === undefined) {
    return res.status(400).json({ success: false, message: "Όλα τα πεδία είναι υποχρεωτικά." });
  }

  if (!attendance[therapistName][date]) {
    attendance[therapistName][date] = {};
  }

  attendance[therapistName][date][time] = {
    childName,
    present,
  };

  writeJSON(attendancePath, attendance, SECRET_KEY);
  res.status(200).json({ success: true, message: "Η παρουσία καταχωρήθηκε επιτυχώς." });
});

// 📌 Fetch therapist schedule
app.get("/schedule/:therapistName", (req, res) => {
  const { therapistName } = req.params;
  const schedules = readJSON(schedulesPath, SECRET_KEY);

  if (!schedules[therapistName]) {
    return res.status(404).json({ success: false, message: "Πρόγραμμα θεραπευτή δεν βρέθηκε." });
  }

  res.status(200).json({ success: true, schedule: schedules[therapistName] });
});

// 📌 Admin/Secretary View All Schedules
app.get("/all-schedules", (req, res) => {
  const schedules = readJSON(schedulesPath); // Read all schedules

  if (!schedules || Object.keys(schedules).length === 0) {
    return res.status(404).json({ success: false, message: "Δεν υπάρχουν προγράμματα θεραπευτών." });
  }

  res.status(200).json({ success: true, schedules });
});

// 📌 List All Users (Admin Only)
app.get("/list-users", (req, res) => {
  console.log("📂 Fetching users...");

  const users = readJSONFile(jsonFiles.users);

  console.log("🔍 Users Data Read:", users);

  if (!users || users.length === 0) {
    return res.status(404).json({ success: false, message: "No users found." });
  }

  res.status(200).json({ success: true, users });
});



// 📌 Admin/Secretary Update a Therapist's Schedule
app.put("/update-schedule", (req, res) => {
  const { therapistName, timeSlot, day, childName } = req.body;
  
  if (!therapistName || !timeSlot || !day) {
    return res.status(400).json({ success: false, message: "Therapist name, time slot, and day are required." });
  }

  const schedules = readJSON(schedulesPath, SECRET_KEY);

  if (!schedules[therapistName]) {
    return res.status(404).json({ success: false, message: "Therapist schedule not found." });
  }

  if (!schedules[therapistName][timeSlot]) {
    return res.status(400).json({ success: false, message: "Invalid time slot." });
  }

  if (!days.includes(day)) {
    return res.status(400).json({ success: false, message: "Invalid day." });
  }

  // Update the schedule
  schedules[therapistName][timeSlot][day] = childName || "";
  writeJSON(schedulesPath, schedules, SECRET_KEY);

  res.status(200).json({ success: true, message: "Το προγραμμα ενημερώθηκε" });
});

////////////////////////////room assignment////////////////////////////////






// 📌 Admin: Add a new room
app.post("/add-room", (req, res) => {
  const { adminRole, roomName, maxCapacity } = req.body;
  if (adminRole !== "Admin") return res.status(403).json({ success: false, message: "Unauthorized." });

  let rooms = readJSONFile(roomsPath);
  if (rooms[roomName]) return res.status(400).json({ success: false, message: "Room already exists." });

  rooms[roomName] = { maxCapacity, assignedTherapists: [] };
  writeJSONFile(roomsPath, rooms);

  res.status(201).json({ success: true, message: "Room added successfully." });
});
//remove room 
app.delete("/remove-room", (req, res) => {
  const { adminRole, roomName } = req.body;
  if (adminRole !== "Admin") return res.status(403).json({ success: false, message: "Unauthorized." });

  let rooms = readJSONFile(roomsPath);
  if (!rooms[roomName]) return res.status(404).json({ success: false, message: "Room not found." });

  delete rooms[roomName];
  writeJSONFile(roomsPath, rooms);

  res.status(200).json({ success: true, message: "Room removed successfully." });
});

// 📌 Assign Therapist to a Room
app.put("/assign-room", (req, res) => {
  const { adminRole, therapistName, roomName } = req.body;
  if (adminRole !== "Admin") return res.status(403).json({ success: false, message: "Unauthorized." });

  let rooms = readJSONFile(roomsPath);
  if (!rooms[roomName]) return res.status(404).json({ success: false, message: "Room not found." });

  if (rooms[roomName].assignedTherapists.includes(therapistName)) {
    return res.status(400).json({ success: false, message: "Therapist already assigned to this room." });
  }

  rooms[roomName].assignedTherapists.push(therapistName);
  writeJSONFile(roomsPath, rooms);
  res.status(200).json({ success: true, message: `Therapist ${therapistName} assigned to room ${roomName}.` });
});

// 📌 Get Room Assignments
app.get("/rooms", (req, res) => {
  const rooms = readJSONFile(roomsPath);
  res.status(200).json({ success: true, rooms });
});
///////////////////////////////////////////////////////////////////////////

// Start the server dynamically based on config
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