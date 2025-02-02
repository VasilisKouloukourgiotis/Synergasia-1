const fs = require("fs");
const path = require("path");
const readline = require("readline");

// Setup readline interface to ask admin for input
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

// Define folder structure
const folders = [
  "frontend/src/components",
  "frontend/src/pages",
  "frontend/public",
  "backend/controllers",
  "backend/models",
  "backend/routes",
  "backend/config"
];

// Create folders
folders.forEach(folder => {
  const folderPath = path.join(__dirname, folder);
  if (!fs.existsSync(folderPath)) {
    fs.mkdirSync(folderPath, { recursive: true });
    console.log(`Created folder: ${folderPath}`);
  }
});

// Ask the admin for the localhost address
rl.question("Enter the backend server address (default: http://localhost:4000): ", (apiBaseUrl) => {
  if (!apiBaseUrl.trim()) {
    apiBaseUrl = "http://localhost:4000"; // Default value
  }

  // Save the config in a JSON file
  const configPath = path.join(__dirname, "backend", "config", "config.json");
  const configData = { apiBaseUrl };

  fs.writeFileSync(configPath, JSON.stringify(configData, null, 2), "utf-8");
  console.log(`✅ Backend API URL set to: ${apiBaseUrl}`);

  rl.close();
});
