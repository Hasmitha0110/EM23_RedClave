/*****************************************************
  Emergency RFID JSON writer + web server
  For ESP32-S2 + MFRC522 (MIFARE Classic tags)
  Wiring: SS = 21, RST = 22, SCK=18, MOSI=23, MISO=19
*****************************************************/

#include <WiFi.h>
#include <WebServer.h>
#include <SPI.h>
#include <MFRC522.h>
#include <ArduinoJson.h>

void handleWrite();
void handleRead();
void handleFormSubmit();
String escapeForJson(String input);

#define SS_PIN 21
#define RST_PIN 22

MFRC522 mfrc522(SS_PIN, RST_PIN);

WebServer server(80);

byte defaultKeyA[6] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };

void setup() {
  Serial.begin(115200);
  SPI.begin();            // Init SPI bus
  mfrc522.PCD_Init();     // Init MFRC522
  delay(50);

  // Start WiFi Access Point
  WiFi.softAP("EmergencyRFID", "emergency123");
  IPAddress apIP = WiFi.softAPIP();
  Serial.print("AP IP address: ");
  Serial.println(apIP);

  // Web server routes
  server.on("/", HTTP_GET, handleRoot);
  server.on("/write", HTTP_POST, handleWrite);
  server.on("/read", HTTP_GET, handleRead);
  server.on("/submit", HTTP_POST, handleFormSubmit);
  server.begin();
  Serial.println("Web server started.");
}

void loop() {
  server.handleClient();
}

/* ------------------ Helper: Wait for tag ------------------- */
bool waitForCard(uint16_t timeoutMs = 10000) {
  uint32_t start = millis();
  while (millis() - start < timeoutMs) {
    if (mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial()) {
      Serial.println("Card detected.");
      return true;
    }
    delay(50);
  }
  Serial.println("Timeout waiting for card.");
  return false;
}

/* ------------------ Authenticate block ------------------- */
bool authBlock(byte blockAddr) {
  MFRC522::MIFARE_Key key;
  for (byte i=0;i<6;i++) key.keyByte[i] = defaultKeyA[i];
  MFRC522::StatusCode status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, blockAddr, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    Serial.print("Auth failed for block "); Serial.print(blockAddr); Serial.print(": ");
    Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }
  return true;
}

/* ------------------ Write JSON to tag ------------------- */
String writeJsonToTag(String json) {
  if (!waitForCard(10000)) return "{\"status\":\"no_tag\"}";

  Serial.print("Card UID: ");
  for (byte i = 0; i < mfrc522.uid.size; i++) {
    Serial.print(mfrc522.uid.uidByte[i] < 0x10 ? " 0" : " ");
    Serial.print(mfrc522.uid.uidByte[i], HEX);
  }
  Serial.println();

  uint16_t len = json.length();
  if (len == 0) return "{\"status\":\"empty_json\"}";
  if (len > 700) return "{\"status\":\"json_too_large\"}";

  // Prepare header
  byte header[16];
  memset(header, 0, 16);
  header[0] = 'J'; header[1] = 'S'; header[2] = 'O'; header[3] = 'N';
  header[4] = (byte)(len & 0xFF);
  header[5] = (byte)((len >> 8) & 0xFF);

  byte headerBlock = 4;
  if (!authBlock(headerBlock)) return "{\"status\":\"auth_fail_header\"}";

  MFRC522::StatusCode stat = mfrc522.MIFARE_Write(headerBlock, header, 16);
  if (stat != MFRC522::STATUS_OK) {
    Serial.print("Header write failed: "); Serial.println(mfrc522.GetStatusCodeName(stat));
    return "{\"status\":\"header_write_failed\"}";
  }
  Serial.println("Header written.");

  // write data starting block 5
  int bytesWritten = 0;
  int block = 5;
  while (bytesWritten < len && block <= 63) {
    // skip sector trailer blocks: 3,7,11... i.e., block %4 == 3
    if (block % 4 == 3) { block++; continue; }

    if (!authBlock(block)) return "{\"status\":\"auth_fail_data\"}";

    byte buff[16];
    for (int i = 0; i < 16; i++) {
      int idx = bytesWritten + i;
      buff[i] = (idx < len) ? (byte)json[idx] : 0x00;
    }
    stat = mfrc522.MIFARE_Write(block, buff, 16);
    if (stat != MFRC522::STATUS_OK) {
      Serial.print("Write failed block "); Serial.print(block); Serial.print(": ");
      Serial.println(mfrc522.GetStatusCodeName(stat));
      return "{\"status\":\"write_failed\"}";
    }
    bytesWritten += 16;
    block++;
    delay(30);
  }

  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
  Serial.println("JSON written successfully.");
  return "{\"status\":\"ok\",\"length\":" + String(len) + "}";
}

/* ------------------ Read JSON from tag ------------------- */
String readJsonFromTag() {
  if (!waitForCard(10000)) return "{\"status\":\"no_tag\"}";

  // Read header block (4)
  if (!authBlock(4)) return "{\"status\":\"auth_fail_header\"}";

  byte headerBuf[18];
  byte headerSize = sizeof(headerBuf);
  MFRC522::StatusCode stat = mfrc522.MIFARE_Read(4, headerBuf, &headerSize);
  if (stat != MFRC522::STATUS_OK) {
    Serial.print("Header read failed: "); Serial.println(mfrc522.GetStatusCodeName(stat));
    return "{\"status\":\"header_read_failed\"}";
  }
  if (!(headerBuf[0]=='J' && headerBuf[1]=='S' && headerBuf[2]=='O' && headerBuf[3]=='N')) {
    return "{\"status\":\"no_json_header\"}";
  }
  uint16_t len = headerBuf[4] | (headerBuf[5] << 8);
  if (len == 0 || len > 1024) return "{\"status\":\"invalid_length\"}";

  String json = "";
  int bytesRead = 0;
  int block = 5;
  while (bytesRead < len && block <= 63) {
    if (block % 4 == 3) { block++; continue; }
    if (!authBlock(block)) return "{\"status\":\"auth_fail_data\"}";

    byte dataBuf[18];
    byte dSize = sizeof(dataBuf);
    stat = mfrc522.MIFARE_Read(block, dataBuf, &dSize);
    if (stat != MFRC522::STATUS_OK) {
      Serial.print("Data read failed block "); Serial.print(block); Serial.print(": ");
      Serial.println(mfrc522.GetStatusCodeName(stat));
      return "{\"status\":\"read_block_failed\"}";
    }
    for (int i = 0; i < 16 && bytesRead < len; i++) {
      if (dataBuf[i] == 0x00) {
        // ignore padding bytes
      } else {
        json += (char)dataBuf[i];
      }
      bytesRead++;
    }
    block++;
    delay(20);
  }

  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
  // Return JSON string (escape for HTTP)
  String res = "{\"status\":\"ok\",\"json\":";
  // JSON inside JSON - encode string safely
  res += "\"" + escapeForJson(json) + "\"}";
  return res;
}

/* ------------------ Form Submission Handler ------------------- */
void handleFormSubmit() {
  // Collect form data
  String fullName = server.arg("fullName");
  String dob = server.arg("dob");
  String bloodType = server.arg("bloodType");
  String contactName = server.arg("contactName");
  String contactRelation = server.arg("contactRelation");
  String contactPhone = server.arg("contactPhone");
  String conditions = server.arg("conditions");
  String allergies = server.arg("allergies");
  String medications = server.arg("medications");
  String insuranceProvider = server.arg("insuranceProvider");
  String insurancePolicy = server.arg("insurancePolicy");
  String advancedDirective = server.arg("advancedDirective");
  String doctorName = server.arg("doctorName");
  String doctorPhone = server.arg("doctorPhone");
  String address = server.arg("address");

  // Create JSON document
  DynamicJsonDocument doc(1024);
  doc["FullName"] = fullName;
  doc["DOB"] = dob;
  doc["BloodType"] = bloodType;
  
  // Create emergency contacts array
  JsonArray contacts = doc.createNestedArray("EmergencyContacts");
  JsonObject contact1 = contacts.createNestedObject();
  contact1["Name"] = contactName;
  contact1["Relation"] = contactRelation;
  contact1["Phone"] = contactPhone;
  
  // Split comma-separated values into arrays
  JsonArray conditionsArray = doc.createNestedArray("Conditions");
  if (conditions.length() > 0) {
    int start = 0;
    int end = conditions.indexOf(',');
    while (end != -1) {
      conditionsArray.add(conditions.substring(start, end));
      start = end + 1;
      end = conditions.indexOf(',', start);
    }
    conditionsArray.add(conditions.substring(start));
  }
  
  JsonArray allergiesArray = doc.createNestedArray("Allergies");
  if (allergies.length() > 0) {
    int start = 0;
    int end = allergies.indexOf(',');
    while (end != -1) {
      allergiesArray.add(allergies.substring(start, end));
      start = end + 1;
      end = allergies.indexOf(',', start);
    }
    allergiesArray.add(allergies.substring(start));
  }
  
  JsonArray medicationsArray = doc.createNestedArray("Medications");
  if (medications.length() > 0) {
    int start = 0;
    int end = medications.indexOf(',');
    while (end != -1) {
      medicationsArray.add(medications.substring(start, end));
      start = end + 1;
      end = medications.indexOf(',', start);
    }
    medicationsArray.add(medications.substring(start));
  }
  
  // Insurance info
  JsonObject insurance = doc.createNestedObject("Insurance");
  insurance["Provider"] = insuranceProvider;
  insurance["Policy"] = insurancePolicy;
  
  // Additional info
  doc["AdvancedDirective"] = advancedDirective;
  doc["DoctorName"] = doctorName;
  doc["DoctorPhone"] = doctorPhone;
  doc["Address"] = address;

  // Serialize JSON to string
  String jsonString;
  serializeJson(doc, jsonString);
  
  Serial.println("Generated JSON: " + jsonString);
  
  // Write to RFID tag
  String result = writeJsonToTag(jsonString);
  server.send(200, "application/json", result);
}

/* ------------------ Web handlers ------------------- */
void handleRoot() {
  String page = R"rawliteral(
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Emergency RFID Medical Data</title>
    <style>
      :root {
        --primary: #0f2027;
        --secondary: #203a43;
        --accent: #2c5364;
        --text: #eee;
        --success: #00e6e6;
        --warning: #ffa500;
      }
      
      * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
      }
      
      body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background: linear-gradient(135deg, var(--primary), var(--secondary), var(--accent));
        color: var(--text);
        line-height: 1.6;
        min-height: 100vh;
        padding: 20px;
      }
      
      .container {
        max-width: 800px;
        margin: 0 auto;
        background: rgba(255,255,255,0.05);
        backdrop-filter: blur(12px);
        border-radius: 20px;
        padding: 30px;
        box-shadow: 0 8px 25px rgba(0,0,0,0.4);
      }
      
      header {
        text-align: center;
        margin-bottom: 30px;
      }
      
      h1 {
        color: var(--success);
        font-size: 2.5em;
        margin-bottom: 10px;
        letter-spacing: 1px;
      }
      
      .subtitle {
        font-size: 1.1em;
        opacity: 0.9;
      }
      
      .form-section {
        margin-bottom: 25px;
        padding: 20px;
        background: rgba(0,0,0,0.3);
        border-radius: 10px;
      }
      
      h2 {
        color: var(--success);
        margin-bottom: 15px;
        font-size: 1.4em;
        border-bottom: 1px solid var(--accent);
        padding-bottom: 5px;
      }
      
      .form-group {
        margin-bottom: 15px;
      }
      
      label {
        display: block;
        margin-bottom: 5px;
        font-weight: 500;
        color: var(--success);
      }
      
      input[type="text"],
      input[type="date"],
      input[type="tel"],
      select,
      textarea {
        width: 100%;
        padding: 12px;
        border: none;
        border-radius: 8px;
        background: rgba(0,0,0,0.6);
        color: var(--text);
        font-size: 1em;
        outline: none;
        transition: all 0.3s ease;
      }
      
      input:focus,
      select:focus,
      textarea:focus {
        box-shadow: 0 0 8px var(--success);
        background: rgba(0,0,0,0.8);
      }
      
      textarea {
        min-height: 80px;
        resize: vertical;
      }
      
      .form-row {
        display: flex;
        gap: 15px;
        flex-wrap: wrap;
      }
      
      .form-row .form-group {
        flex: 1;
        min-width: 200px;
      }
      
      .btn-group {
        display: flex;
        gap: 15px;
        justify-content: center;
        margin-top: 30px;
        flex-wrap: wrap;
      }
      
      .btn {
        padding: 14px 28px;
        border: none;
        border-radius: 8px;
        font-size: 1.1em;
        font-weight: bold;
        cursor: pointer;
        transition: all 0.3s ease;
        min-width: 160px;
      }
      
      .btn-primary {
        background: linear-gradient(135deg, var(--success), #007a7a);
        color: white;
      }
      
      .btn-secondary {
        background: linear-gradient(135deg, #666, #444);
        color: white;
      }
      
      .btn:hover {
        transform: translateY(-2px);
        box-shadow: 0 5px 15px rgba(0,230,230,0.4);
      }
      
      .result-container {
        margin-top: 30px;
        padding: 20px;
        background: rgba(0,0,0,0.3);
        border-radius: 10px;
      }
      
      #result {
        background: rgba(0,0,0,0.7);
        padding: 15px;
        border-radius: 8px;
        font-family: monospace;
        white-space: pre-wrap;
        word-wrap: break-word;
        min-height: 100px;
        color: var(--success);
      }
      
      .instructions {
        background: rgba(255,255,255,0.1);
        padding: 15px;
        border-radius: 8px;
        margin-bottom: 20px;
        font-size: 0.9em;
      }
      
      .instructions ul {
        padding-left: 20px;
      }
      
      .instructions li {
        margin-bottom: 5px;
      }

      .medical-report {
    background: rgba(255,255,255,0.1);
    border-radius: 12px;
    padding: 0;
    overflow: hidden;
}

.report-header {
    background: linear-gradient(135deg, #ff6b6b, #ee5a24);
    color: white;
    padding: 15px 20px;
    text-align: center;
}

.report-header h2 {
    margin: 0 0 8px 0;
    color: white;
    font-size: 1.6em;
}

.patient-id {
    font-size: 1em;
    opacity: 0.9;
}

.report-section {
    padding: 15px 20px;
    border-bottom: 1px solid rgba(255,255,255,0.1);
}

.report-section:last-child {
    border-bottom: none;
}

.report-section h3 {
    color: #00e6e6;
    margin-bottom: 12px;
    font-size: 1.2em;
}

.report-section h4 {
    color: #ffa500;
    margin-bottom: 8px;
    font-size: 1em;
}

.info-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 12px;
}

.info-item {
    display: flex;
    flex-direction: column;
}

.info-item label {
    font-weight: bold;
    color: #00e6e6;
    margin-bottom: 4px;
    font-size: 0.85em;
}

.info-item span {
    color: white;
    font-size: 1em;
}

.blood-type {
    background: #ff4757;
    color: white;
    padding: 3px 10px;
    border-radius: 15px;
    font-weight: bold;
    display: inline-block;
    width: fit-content;
    font-size: 0.9em;
}

.contact-card {
    background: rgba(0,230,230,0.1);
    padding: 12px;
    border-radius: 8px;
    margin-bottom: 8px;
}

.contact-name {
    font-weight: bold;
    color: #00e6e6;
    font-size: 1em;
}

.contact-details {
    display: flex;
    justify-content: space-between;
    margin-top: 4px;
    color: #ccc;
    font-size: 0.9em;
}

.phone {
    color: #00e6e6;
    font-weight: bold;
}

.medical-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
}

.medical-category ul {
    list-style: none;
    padding: 0;
    margin: 0;
}

.medical-category li {
    background: rgba(255,255,255,0.05);
    padding: 6px 10px;
    margin-bottom: 4px;
    border-radius: 4px;
    border-left: 3px solid #00e6e6;
    font-size: 0.9em;
}

.warning {
    background: rgba(255,165,0,0.1);
    border-left: 4px solid #ffa500;
    padding: 12px 20px;
}

.report-footer {
    background: rgba(0,0,0,0.3);
    padding: 10px 15px;
    text-align: center;
    color: #ccc;
    font-size: 0.8em;
}

.error {
    background: rgba(255,0,0,0.1);
    color: #ff6b6b;
    padding: 12px;
    border-radius: 8px;
    border-left: 4px solid #ff6b6b;
}

/* Remove extra margins from paragraphs */
.report-section p {
    margin: 8px 0;
    font-size: 0.9em;
}

@media (max-width: 600px) {
    .report-section {
        padding: 12px 15px;
    }
    
    .info-grid {
        grid-template-columns: 1fr;
        gap: 10px;
    }
    
    .medical-grid {
        grid-template-columns: 1fr;
        gap: 12px;
    }
    
    .contact-details {
        flex-direction: column;
        gap: 2px;
    }
    
    .report-header {
        padding: 12px 15px;
    }
    
    .report-header h2 {
        font-size: 1.4em;
    }
}

.patient-id {
    font-size: 1.1em;
    opacity: 0.9;
}

.report-section {
    padding: 20px;
    border-bottom: 1px solid rgba(255,255,255,0.1);
}

.report-section:last-child {
    border-bottom: none;
}

.report-section h3 {
    color: #00e6e6;
    margin-bottom: 15px;
    font-size: 1.3em;
}

.report-section h4 {
    color: #ffa500;
    margin-bottom: 10px;
    font-size: 1.1em;
}

.info-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 15px;
}

.info-item {
    display: flex;
    flex-direction: column;
}

.info-item label {
    font-weight: bold;
    color: #00e6e6;
    margin-bottom: 5px;
    font-size: 0.9em;
}

.info-item span {
    color: white;
    font-size: 1.1em;
}

.blood-type {
    background: #ff4757;
    color: white;
    padding: 4px 12px;
    border-radius: 20px;
    font-weight: bold;
    display: inline-block;
    width: fit-content;
}

.contact-card {
    background: rgba(0,230,230,0.1);
    padding: 15px;
    border-radius: 10px;
    margin-bottom: 10px;
}

.contact-name {
    font-weight: bold;
    color: #00e6e6;
    font-size: 1.1em;
}

.contact-details {
    display: flex;
    justify-content: space-between;
    margin-top: 5px;
    color: #ccc;
}

.phone {
    color: #00e6e6;
    font-weight: bold;
}

.medical-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 20px;
}

.medical-category ul {
    list-style: none;
    padding: 0;
    margin: 0;
}

.medical-category li {
    background: rgba(255,255,255,0.05);
    padding: 8px 12px;
    margin-bottom: 5px;
    border-radius: 5px;
    border-left: 3px solid #00e6e6;
}

.warning {
    background: rgba(255,165,0,0.1);
    border-left: 5px solid #ffa500;
}

.report-footer {
    background: rgba(0,0,0,0.3);
    padding: 15px;
    text-align: center;
    color: #ccc;
    font-size: 0.9em;
}

.error {
    background: rgba(255,0,0,0.1);
    color: #ff6b6b;
    padding: 15px;
    border-radius: 10px;
    border-left: 5px solid #ff6b6b;
}

@media (max-width: 600px) {
    .info-grid {
        grid-template-columns: 1fr;
    }
    
    .medical-grid {
        grid-template-columns: 1fr;
    }
    
    .contact-details {
        flex-direction: column;
    }
}
      
      @media (max-width: 600px) {
        .container {
          padding: 15px;
        }
        
        h1 {
          font-size: 2em;
        }
        
        .form-row {
          flex-direction: column;
        }
        
        .btn-group {
          flex-direction: column;
        }
        
        .btn {
          width: 100%;
        }
      }
    </style>
  </head>
  <body>
    <div class="container">
      <header>
        <h1>🚑 Emergency Medical RFID</h1>
        <p class="subtitle">Fill your medical information and write to RFID tag</p>
      </header>
      
      <div class="instructions">
        <p><strong>Instructions:</strong></p>
        <ul>
          <li>Fill in all relevant medical information</li>
          <li>For lists (conditions, allergies, medications), separate items with commas</li>
          <li>Click "Write to RFID Tag" and place your tag on the reader when prompted</li>
          <li>Use "Read RFID Tag" to verify stored data</li>
        </ul>
      </div>
      
      <form id="medicalForm">
        <!-- Personal Information -->
        <div class="form-section">
          <h2>Personal Information</h2>
          <div class="form-row">
            <div class="form-group">
              <label for="fullName">Full Name *</label>
              <input type="text" id="fullName" name="fullName" required placeholder="John Doe">
            </div>
            <div class="form-group">
              <label for="dob">Date of Birth</label>
              <input type="date" id="dob" name="dob">
            </div>
            <div class="form-group">
              <label for="bloodType">Blood Type</label>
              <select id="bloodType" name="bloodType">
                <option value="">Select Blood Type</option>
                <option value="A+">A+</option>
                <option value="A-">A-</option>
                <option value="B+">B+</option>
                <option value="B-">B-</option>
                <option value="AB+">AB+</option>
                <option value="AB-">AB-</option>
                <option value="O+">O+</option>
                <option value="O-">O-</option>
              </select>
            </div>
          </div>
          <div class="form-group">
            <label for="address">Address</label>
            <input type="text" id="address" name="address" placeholder="123 Main St, City, Country">
          </div>
        </div>
        
        <!-- Emergency Contact -->
        <div class="form-section">
          <h2>Emergency Contact</h2>
          <div class="form-row">
            <div class="form-group">
              <label for="contactName">Contact Name</label>
              <input type="text" id="contactName" name="contactName" placeholder="Jane Doe">
            </div>
            <div class="form-group">
              <label for="contactRelation">Relation</label>
              <input type="text" id="contactRelation" name="contactRelation" placeholder="Spouse">
            </div>
            <div class="form-group">
              <label for="contactPhone">Phone Number</label>
              <input type="tel" id="contactPhone" name="contactPhone" placeholder="+1 234 567 8900">
            </div>
          </div>
        </div>
        
        <!-- Medical Information -->
        <div class="form-section">
          <h2>Medical Information</h2>
          <div class="form-group">
            <label for="conditions">Medical Conditions (comma separated)</label>
            <textarea id="conditions" name="conditions" placeholder="Asthma, Diabetes, Hypertension"></textarea>
          </div>
          <div class="form-group">
            <label for="allergies">Allergies (comma separated)</label>
            <textarea id="allergies" name="allergies" placeholder="Penicillin, Peanuts, Latex"></textarea>
          </div>
          <div class="form-group">
            <label for="medications">Current Medications (comma separated)</label>
            <textarea id="medications" name="medications" placeholder="Insulin, Lisinopril 10mg"></textarea>
          </div>
        </div>
        
        <!-- Doctor Information -->
        <div class="form-section">
          <h2>Doctor Information</h2>
          <div class="form-row">
            <div class="form-group">
              <label for="doctorName">Primary Doctor</label>
              <input type="text" id="doctorName" name="doctorName" placeholder="Dr. Smith">
            </div>
            <div class="form-group">
              <label for="doctorPhone">Doctor Phone</label>
              <input type="tel" id="doctorPhone" name="doctorPhone" placeholder="+1 234 567 8901">
            </div>
          </div>
        </div>
        
        <!-- Insurance & Other -->
        <div class="form-section">
          <h2>Insurance & Additional Information</h2>
          <div class="form-row">
            <div class="form-group">
              <label for="insuranceProvider">Insurance Provider</label>
              <input type="text" id="insuranceProvider" name="insuranceProvider" placeholder="ABC Health Insurance">
            </div>
            <div class="form-group">
              <label for="insurancePolicy">Policy Number</label>
              <input type="text" id="insurancePolicy" name="insurancePolicy" placeholder="POL123456789">
            </div>
          </div>
          <div class="form-group">
            <label for="advancedDirective">Advanced Directive / Special Instructions</label>
            <textarea id="advancedDirective" name="advancedDirective" placeholder="Do not resuscitate, Living will location, etc."></textarea>
          </div>
        </div>
        
        <div class="btn-group">
          <button type="button" class="btn btn-primary" onclick="submitForm()">Write to RFID Tag</button>
          <button type="button" class="btn btn-secondary" onclick="readTag()">Read RFID Tag</button>
        </div>
      </form>
      
      <div class="result-container">
        <h2>Operation Result</h2>
        <pre id="result">No action performed yet.</pre>
      </div>
    </div>

    <script>
      function submitForm() {
        const form = document.getElementById('medicalForm');
        const formData = new FormData(form);
        
        document.getElementById('result').textContent = "⏳ Processing... Please place RFID tag on reader now.";
        
        fetch('/submit', {
          method: 'POST',
          body: formData
        })
        .then(response => response.json())
        .then(data => {
          document.getElementById('result').textContent = JSON.stringify(data, null, 2);
        })
        .catch(error => {
          document.getElementById('result').textContent = 'Error: ' + error;
        });
      }
      
function readTag() {
    document.getElementById("result").innerHTML = "📡 Reading tag... Please place RFID tag on reader now.";
    
    fetch('/read')
    .then(response => response.json())
    .then(data => {
        if (data.status === 'ok') {
            try {
                const jsonData = JSON.parse(data.json);
                const reportHTML = generateMedicalReport(jsonData);
                document.getElementById("result").innerHTML = reportHTML;
            } catch(e) {
                document.getElementById("result").innerHTML = '<div class="error">Error parsing data: ' + e + '</div>';
            }
        } else {
            document.getElementById("result").innerHTML = '<div class="error">' + JSON.stringify(data, null, 2) + '</div>';
        }
    })
    .catch(error => {
        document.getElementById("result").innerHTML = '<div class="error">Error: ' + error + '</div>';
    });
}

function generateMedicalReport(patientData) {
    return `
        <div class="medical-report">
            <div class="report-header">
                <h2>🚑 Medical Emergency Report</h2>
                <div class="patient-id">ID: ${patientData.FullName || 'Unknown'}</div>
            </div>
            
            <div class="report-section">
                <h3>👤 Personal Information</h3>
                <div class="info-grid">
                    <div class="info-item">
                        <label>Full Name:</label>
                        <span>${patientData.FullName || 'Not provided'}</span>
                    </div>
                    <div class="info-item">
                        <label>Date of Birth:</label>
                        <span>${patientData.DOB || 'Not provided'}</span>
                    </div>
                    <div class="info-item">
                        <label>Blood Type:</label>
                        <span class="blood-type">${patientData.BloodType || 'Not provided'}</span>
                    </div>
                    <div class="info-item">
                        <label>Address:</label>
                        <span>${patientData.Address || 'Not provided'}</span>
                    </div>
                </div>
            </div>
            
            <div class="report-section">
                <h3>📞 Emergency Contact</h3>
                ${patientData.EmergencyContacts && patientData.EmergencyContacts.length > 0 ? 
                    patientData.EmergencyContacts.map(contact => `
                        <div class="contact-card">
                            <div class="contact-name">${contact.Name || 'N/A'}</div>
                            <div class="contact-details">
                                <span>${contact.Relation || ''}</span>
                                <span class="phone">${contact.Phone || ''}</span>
                            </div>
                        </div>
                    `).join('') : 
                    '<p>No emergency contacts provided</p>'
                }
            </div>
            
            <div class="report-section">
                <h3>🏥 Medical Details</h3>
                <div class="medical-grid">
                    <div class="medical-category">
                        <h4>Conditions</h4>
                        ${patientData.Conditions && patientData.Conditions.length > 0 ? 
                            `<ul>${patientData.Conditions.map(condition => `<li>${condition}</li>`).join('')}</ul>` : 
                            '<p>None reported</p>'
                        }
                    </div>
                    <div class="medical-category">
                        <h4>Allergies</h4>
                        ${patientData.Allergies && patientData.Allergies.length > 0 ? 
                            `<ul>${patientData.Allergies.map(allergy => `<li>${allergy}</li>`).join('')}</ul>` : 
                            '<p>None reported</p>'
                        }
                    </div>
                    <div class="medical-category">
                        <h4>Medications</h4>
                        ${patientData.Medications && patientData.Medications.length > 0 ? 
                            `<ul>${patientData.Medications.map(med => `<li>${med}</li>`).join('')}</ul>` : 
                            '<p>None reported</p>'
                        }
                    </div>
                </div>
            </div>
            
            <div class="report-section">
                <h3>💊 Insurance & Medical</h3>
                <div class="info-grid">
                    <div class="info-item">
                        <label>Insurance Provider:</label>
                        <span>${patientData.Insurance?.Provider || 'Not provided'}</span>
                    </div>
                    <div class="info-item">
                        <label>Policy Number:</label>
                        <span>${patientData.Insurance?.Policy || 'Not provided'}</span>
                    </div>
                    <div class="info-item">
                        <label>Primary Doctor:</label>
                        <span>${patientData.DoctorName || 'Not provided'}</span>
                    </div>
                    <div class="info-item">
                        <label>Doctor Phone:</label>
                        <span>${patientData.DoctorPhone || 'Not provided'}</span>
                    </div>
                </div>
            </div>
            
            ${patientData.AdvancedDirective ? `
            <div class="report-section warning">
                <h3>⚠️ Advanced Directive</h3>
                <p>${patientData.AdvancedDirective}</p>
            </div>
            ` : ''}
            
            <div class="report-footer">
                <small>This information was retrieved from RFID medical tag</small>
            </div>
        </div>
    `;
}
      
      // Set today's date as default for DOB (optional)
      window.addEventListener('load', function() {
        const today = new Date().toISOString().split('T')[0];
        document.getElementById('dob').value = today;
      });
    </script>
  </body>
  </html>
  )rawliteral";
  server.send(200, "text/html", page);
}

void handleWrite() {
  String body = server.arg("plain");
  Serial.println("Write request received. Length: " + String(body.length()));
  String res = writeJsonToTag(body);
  server.send(200, "application/json", res);
}

void handleRead() {
  Serial.println("Read request received.");
  String res = readJsonFromTag();
  server.send(200, "application/json", res);
}

/* ------------------ Utility: escape string for JSON value ------------------- */
String escapeForJson(String input) {
  input.replace("\\", "\\\\");
  input.replace("\"", "\\\"");
  input.replace("\n", "\\n");
  input.replace("\r", "\\r");
  return input;
}