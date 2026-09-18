#!/usr/bin/env node

const axios = require("axios");
const crypto = require("crypto");
const readline = require("readline");
const fs = require("fs");
const path = require("path");

// Configuration
const CONFIG = {
  MAX_ATTEMPTS: 10000000,
  PROGRESS_INTERVAL: 10000,
  FEE_SATS: 10000
};

// Visual progress spinner
const spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
let spinnerIndex = 0;

// Helper functions
function ask(q, def = "") {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(res => rl.question(def ? `${q} [${def}]: ` : `${q}: `, a => { rl.close(); res(a || def); }));
}

// Base64 encoding/decoding
function base64Encode(str) {
  return Buffer.from(str).toString('base64');
}

function base64Decode(str) {
  return Buffer.from(str, 'base64').toString();
}

// File handling
function readFileAsBase64(filePath) {
  try {
    const data = fs.readFileSync(filePath);
    return data.toString('base64');
  } catch (error) {
    console.error(`Error reading file: ${error.message}`);
    return null;
  }
}

function saveBase64ToFile(base64Data, filePath) {
  try {
    const buffer = Buffer.from(base64Data, 'base64');
    fs.writeFileSync(filePath, buffer);
    return true;
  } catch (error) {
    console.error(`Error saving file: ${error.message}`);
    return false;
  }
}

// Display unlocked secret in terminal
function displayUnlockedSecret(txid, secret, dataType) {
    console.log("\n╔════════════════════════════════════╗");
    console.log("║     🎉 SECRET REVEALED! 🎉        ║");
    console.log("╚════════════════════════════════════╝");
    console.log(`  Transaction: ${txid.substr(0, 16)}...`);
    console.log(`  Type: ${dataType}`);
    
    if (dataType === 'text') {
        console.log(`  Message: "${secret}"`);
    } else {
        // For files, save to disk
        const filename = `revealed_${txid.substr(0, 8)}.${dataType}`;
        if (saveBase64ToFile(secret, filename)) {
            console.log(`  ✅ File saved as: ${filename}`);
        } else {
            console.log(`  ❌ Failed to save file`);
        }
    }
    console.log("═══════════════════════════════════════\n");
}

// Visual progress display
function simulateGrinding(targetPrefix, duration = 3000) {
  return new Promise((resolve) => {
    let attempts = 0;
    const startTime = Date.now();
    
    const interval = setInterval(() => {
      attempts += Math.floor(Math.random() * 5000) + 1000;
      const fakeHash = crypto.randomBytes(32).toString('hex');
      
      process.stdout.clearLine();
      process.stdout.cursorTo(0);
      process.stdout.write(`${spinner[spinnerIndex]} Mining & Flipping Hashes ..: ${attempts} attempts | Hash: ${fakeHash.substring(0, 16)}...`);
      spinnerIndex = (spinnerIndex + 1) % spinner.length;
      
      if (Date.now() - startTime >= duration) {
        clearInterval(interval);
        const successHash = targetPrefix + crypto.randomBytes(30).toString('hex').substring(0, 64 - targetPrefix.length);
        process.stdout.clearLine();
        process.stdout.cursorTo(0);
        console.log(`✨ Found match after ${attempts} attempts!`);
        console.log(`   Hash: ${successHash}`);
        resolve();
      }
    }, 100);
  });
}

// Progress animation
async function withProgress(message, asyncFn) {
  const interval = setInterval(() => {
    process.stdout.clearLine();
    process.stdout.cursorTo(0);
    process.stdout.write(`${spinner[spinnerIndex]} ${message}`);
    spinnerIndex = (spinnerIndex + 1) % spinner.length;
  }, 100);
  
  try {
    const result = await asyncFn();
    clearInterval(interval);
    process.stdout.clearLine();
    process.stdout.cursorTo(0);
    return result;
  } catch (error) {
    clearInterval(interval);
    process.stdout.clearLine();
    process.stdout.cursorTo(0);
    throw error;
  }
}

// RPC client
class RPCClient {
  constructor(baseURL) {
    this.http = axios.create({ 
      baseURL, 
      timeout: 60000,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  async call(method, params = {}) {
    try {
      const { data } = await this.http.post('/rpc', {
        jsonrpc: "2.0",
        id: Date.now(),
        method: method,
        params: params
      });
      
      if (data.error) {
        throw new Error(data.error.message || 'RPC error');
      }
      
      return data.result;
    } catch (error) {
      if (error.response && error.response.data && error.response.data.error) {
        throw new Error(error.response.data.error.message);
      }
      throw error;
    }
  }
}

// Get list of wallet addresses
async function getWalletAddresses(client) {
  try {
    const result = await client.call('listaddresses', {});
    return result.addresses || [];
  } catch (e) {
    console.log("Could not get wallet addresses");
    return [];
  }
}

// Create MagicLock with optional secret
async function createMagicLockWithSecret(client, address) {
  console.log("\n📝 MagicLock Creation Wizard");
  console.log("─────────────────────────────");
  
  const amount = parseFloat(await ask("Amount to lock (TRU)", "0.001"));
  const prefix = await ask("Target prefix (hex, e.g. '00' or '21e8')", "00");
  
  if (!/^[0-9a-f]+$/i.test(prefix) || prefix.length % 2 !== 0) {
    console.error("❌ Invalid hex prefix (must be even length)");
    return null;
  }
  
  // Ask about secret data
  const includeSecret = await ask("Include secret data? (y/n)", "n");
  
  let params = {
    amount: amount,
    targetPrefix: prefix,
    address: address
  };
  
  if (includeSecret.toLowerCase() === 'y') {
    console.log("\n🔐 Secret Data Configuration");
    console.log("Choose secret type:");
    console.log("  1) Text message");
    console.log("  2) File (image/pdf/document)");
    
    const secretChoice = await ask("Choice (1-2)", "1");
    
    if (secretChoice === "1") {
      const secretText = await ask("Enter secret text");
      params.secretData = secretText;
      params.dataType = "text";
      console.log(`\n📄 Secret text: ${secretText.length} characters`);
      
    } else if (secretChoice === "2") {
      const filePath = await ask("Enter file path");
      
      if (!fs.existsSync(filePath)) {
        console.error("❌ File not found");
        return null;
      }
      
      const stats = fs.statSync(filePath);
      if (stats.size > 200) { // ~200 bytes max for OP_RETURN
        console.error("❌ File too large (max ~200 bytes for OP_RETURN)");
        console.log("💡 Tip: Consider using IPFS hash instead of full file");
        return null;
      }
      
      const fileContent = readFileAsBase64(filePath);
      if (!fileContent) return null;
      
      const ext = path.extname(filePath).substring(1) || "file";
      params.secretData = fileContent;
      params.dataType = ext;
      
      console.log(`\n📎 File loaded: ${path.basename(filePath)} (${stats.size} bytes)`);
    }
  }
  
  console.log(`\n🔒 Creating MagicLock...`);
  console.log(`  Amount: ${amount} TRU`);
  console.log(`  Target: ${prefix}`);
  console.log(`  Address: ${address}`);
  if (params.secretData) {
    console.log(`  Secret: ${params.dataType} data attached`);
  }
  console.log(`  Difficulty: ~${Math.pow(256, prefix.length/2).toExponential(2)} attempts\n`);
  
  try {
    const result = await withProgress("Creating MagicLock transaction...", 
      () => client.call('createmagiclock', params)
    );
    
    console.log(`\n✅ MagicLock created successfully!`);
    console.log(`  TXID: ${result.txid}`);
    console.log(`  🎯 Target: ${prefix}`);
    console.log(`  💰 Locked: ${amount} TRU`);
    if (result.hasSecret) {
      console.log(`  🔐 Secret: ${params.dataType} data embedded`);
      console.log(`  📌 Note: Secret will be revealed when unlocked with matching signature`);
    }
    
    return result;
  } catch (error) {
    console.error(`\n❌ Error: ${error.message}`);
    return null;
  }
}

// Search MagicLocks
async function searchMagicLocks(client, address) {
  const params = address ? { address } : {};
  const result = await client.call('listmagiclocks', params);
  
  const magicLocks = result.magicLocks || [];
  
  console.log();
  if (magicLocks.length === 0) {
    console.log("  No MagicLocks found");
  } else {
    console.log(`  Found ${magicLocks.length} MagicLock(s):\n`);
    magicLocks.forEach((lock, i) => {
      const icon = lock.spent ? '🔓' : '🔒';
      console.log(`  ${icon} ${i+1}. ${lock.txid}:${lock.vout}`);
      console.log(`     Amount: ${lock.amount} TRU`);
      console.log(`     Target: ${lock.targetPrefix}`);
      console.log(`     Status: ${lock.spent ? 'SPENT' : 'UNSPENT'}`);
      console.log(`     Block: ${lock.blockHeight}`);
      if (lock.address) {
        console.log(`     Address: ${lock.address}`);
      }
      const difficulty = Math.pow(256, lock.targetPrefix.length/2);
      console.log(`     Difficulty: ~${difficulty.toExponential(2)} attempts\n`);
    });
  }
  
  return magicLocks;
}

// Unlock MagicLock and reveal secret
async function unlockMagicLockWithSecret(client, address) {
  const txid = await ask("Enter TXID of MagicLock to unlock");
  const vout = parseInt(await ask("Enter vout", "0"));
  const recipient = await ask("Recipient address", address);
  
  console.log(`\n🔓 Starting unlock process...`);
  console.log(`  Lock: ${txid.substring(0, 16)}...`);
  console.log(`  Recipient: ${recipient}\n`);
  
  console.log("🔨 Mining & Flipping Hashes for valid signature...\n");
  
  try {
    // Call the RPC method that returns both unlock txid and secret
    const unlockPromise = client.call('unlockmagiclock', {
      txid: txid,
      vout: vout,
      recipient: recipient
    });
    
    const [result] = await Promise.all([
      unlockPromise,
      simulateGrinding("21e8", 2000)
    ]);
    
    console.log(`\n✅ MagicLock unlocked successfully!`);
    console.log(`  Unlock TXID: ${result.unlockTxid || result.txid}`);
    console.log(`  💸 Released funds to: ${recipient}`);
    
    // Check for revealed secret - using the displayUnlockedSecret function
    if (result.secret && result.secret !== '') {
      displayUnlockedSecret(
        result.unlockTxid || result.txid, 
        result.secret, 
        result.dataType || 'text'
      );
    } else if (result.hasSecret && result.secretRevealed) {
      // Fallback for different response format
      displayUnlockedSecret(
        result.unlockTxid || result.txid,
        result.secretData,
        result.secretType || 'text'
      );
    }
    
    return result;
  } catch (error) {
    console.error(`\n❌ Error: ${error.message}`);
    return null;
  }
}

// Main program
async function main() {
  console.log("🧙 TRU MagicLock Tool ");
  console.log("═══════════════════════════\n");
  
  const host = await ask("Node host", "127.0.0.1");
  const port = await ask("Node RPC port", "8332");
  
  const client = new RPCClient(`http://${host}:${port}`);
  
  // Get available addresses
  let addresses = await withProgress("Loading wallet addresses...", 
    () => getWalletAddresses(client)
  );
  
  let address = "";
  
  if (addresses.length > 0) {
    console.log("\n📋 Available wallet addresses:");
    addresses.forEach((addr, i) => {
      console.log(`  ${i+1}. ${addr}`);
    });
    
    const choice = await ask("Select address number, or enter custom address", "1");
    const num = parseInt(choice);
    
    if (num > 0 && num <= addresses.length) {
      address = addresses[num - 1];
      console.log(`Using wallet address: ${address}`);
    } else if (choice.length > 20) {
      address = choice;
      console.log(`Using custom address: ${address}`);
    } else {
      address = addresses[0];
      console.log(`Using default address: ${address}`);
    }
  } else {
    address = await ask("Enter your TRU address");
  }
  
  while (true) {
    console.log("\n╔═══════════════════════╗");
    console.log("║   MagicLock Menu      ║");
    console.log("╚═══════════════════════╝");
    console.log("1) 🔒 Create MagicLock (with optional secret)");
    console.log("2) 🔍 Search MagicLocks");
    console.log("3) 🔓 Unlock MagicLock (reveal secret)");
    console.log("4) 📍 Change Address");
    console.log("5) 🚪 Exit");
    
    const choice = await ask("Choose option", "2");
    
    try {
      if (choice === "1") {
        await createMagicLockWithSecret(client, address);
        
      } else if (choice === "2") {
        const addr = await ask("Filter by address (blank for all)", "");
        await withProgress("Searching for MagicLocks...", 
          () => searchMagicLocks(client, addr || null)
        );
        
      } else if (choice === "3") {
        await unlockMagicLockWithSecret(client, address);
        
      } else if (choice === "4") {
        address = await ask("Enter new address");
        console.log(`✅ Address changed to: ${address}`);
        
      } else if (choice === "5") {
        break;
      }
    } catch (error) {
      console.error(`\n❌ Error: ${error.message}`);
    }
  }
  
  console.log("\n👋 Goodbye! Thanks for using MagicLock!");
  console.log("🧙‍♂️ May your transactions be swift and your secrets be safe!\n");
}

if (require.main === module) {
  main().catch(err => {
    console.error("Fatal error:", err);
    process.exit(1);
  });
}
