const nodeCrypto = require('crypto');
const Hyperswarm = require('hyperswarm');
const Corestore = require('corestore');
const Hyperdrive = require('hyperdrive');
const HypercoreId = require('hypercore-id-encoding');
const Protomux = require('protomux');
const SecretStream = require('@hyperswarm/secret-stream');
const c = require('compact-encoding');
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const { Command } = require('commander');
const goodbye = require('graceful-goodbye');
const crayon = require('tiny-crayon');
const { x25519 } = require('@noble/curves/ed25519');
const { sha256 } = require('@noble/hashes/sha256');
const { concatBytes } = require('@noble/hashes/utils');
const { pbkdf2 } = require('@noble/hashes/pbkdf2');
const { hmac } = require('@noble/hashes/hmac');
const os = require('os');
const { pipeline } = require('stream/promises');
var singleLineLog = require('single-line-log').stdout;
process.stdout.isTTY = true;

const WORDLIST = [
    'aardvark', 'absurd', 'accrue', 'acme', 'adrift', 'adult', 'afflict', 'ahead', 'aimless', 'algol', 'allow', 'alone',
    'ammo', 'ancient', 'apple', 'artist', 'assume', 'athens', 'atlas', 'aztec', 'baboon', 'backfield', 'backward', 'banjo',
    'beaming', 'bedlamp', 'beehive', 'beeswax', 'befriend', 'belfast', 'berserk', 'billiard', 'bison', 'blackjack', 'blockade', 'blowtorch',
    'bluebird', 'bombast', 'bookshelf', 'brackish', 'breadline', 'breakup', 'brickyard', 'briefcase', 'burbank', 'button', 'buzzard', 'cement',
    'chairlift', 'chatter', 'checkup', 'chisel', 'choking', 'chopper', 'christmas', 'clamshell', 'classic', 'classroom', 'cleanup', 'clockwork',
    'cobra', 'commence', 'concert', 'cowbell', 'crackdown', 'cranky', 'crowfoot', 'crucial', 'crumpled', 'crusade', 'cubic', 'dashboard',
    'deadbolt', 'deckhand', 'dogsled', 'dragnet', 'drainage', 'dreadful', 'drifter', 'dropper', 'drumbeat', 'drunken', 'dupont', 'dwelling',
    'eating', 'edict', 'egghead', 'eightball', 'endorse', 'endow', 'enlist', 'erase', 'escape', 'exceed', 'eyeglass', 'eyetooth'
];

// Protocol constants
const PROTOCOLS = {
    KEY_EXCHANGE: 'hyperwormhole/key-exchange/1.0.0',
    DRIVE_EXCHANGE: 'hyperwormhole/drive-exchange/1.0.0',
    CONTROL: 'hyperwormhole/control/1.0.0'
};

class ImprovedSPAKE2 {
    constructor() {
        this.M = x25519.utils.randomPrivateKey();
        this.N = x25519.utils.randomPrivateKey();
    }

    generateKeyPair() {
        const privateKey = x25519.utils.randomPrivateKey();
        const publicKey = x25519.getPublicKey(privateKey);
        return { privateKey, publicKey };
    }

    hashPassword(password) {
        const salt = nodeCrypto.randomBytes(16);
        const key = pbkdf2(sha256, password, salt, { c: 10000, dkLen: 32 });
        return { key, salt };
    }

    computeX(isAlice, privateKey, passwordHash) {
        const point = isAlice ? this.M : this.N;
        const xPrivate = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
            xPrivate[i] = privateKey[i] ^ passwordHash[i];
        }
        const X = x25519.getPublicKey(xPrivate);
        return { xPrivate, X };
    }

    computeSharedSecret(xPrivate, Y) {
        return x25519.getSharedSecret(xPrivate, Y);
    }

    deriveSessionKey(isAlice, X, Y, sharedSecret) {
        const info = concatBytes(
            new TextEncoder().encode("SPAKE2 Key Derivation"),
            isAlice ? X : Y,
            isAlice ? Y : X
        );
        return hmac(sha256, sharedSecret, info);
    }

    generateConfirmation(sessionKey) {
        return hmac(sha256, sessionKey, new TextEncoder().encode("Confirmation"));
    }

    verifyConfirmation(sessionKey, confirmation) {
        const expected = this.generateConfirmation(sessionKey);
        return nodeCrypto.timingSafeEqual(expected, confirmation);
    }

    bytesToHex(bytes) {
        return Buffer.from(bytes).toString('hex');
    }
}

class HyperWormhole {
    constructor(options = {}) {
        this.options = options;
        this.spake2 = new ImprovedSPAKE2();
        this.tempDir = null;
        this.totalSize = 0;
        this.transferredSize = 0;
        this.monitors = new Set();
    }

    async createTempCorestore() {
        this.tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hyperwormhole-'));
        return new Corestore(this.tempDir);
    }

    async cleanup() {
        // Close all monitors
        for (const monitor of this.monitors) {
            await monitor.close();
        }
        this.monitors.clear();
        if (this.tempDir) {
            await fs.rm(this.tempDir, { recursive: true, force: true });
            this.tempDir = null;
        }
    }

    async performKeyAndDriveExchange(mux, wormholeCode, drive, isAlice) {
        return new Promise(async (resolve, reject) => {
            try {
                const { key: passwordHash, salt } = this.spake2.hashPassword(wormholeCode);
                const keyPair = this.spake2.generateKeyPair();
                const result = this.spake2.computeX(isAlice, keyPair.privateKey, passwordHash);

                let sessionKey = null;
                let driveKeyResult = null;

                // Create key exchange channel
                const keyExchangeChannel = mux.createChannel({
                    protocol: PROTOCOLS.KEY_EXCHANGE,
                    onopen() {
                        console.log("Key exchange channel opened", (isAlice ? 'Alice' : 'Bob'));
                        if (isAlice) {
                            console.log('Alice sending salt + X value');
                            const payload = Buffer.concat([salt, result.X]);
                            aliceToBox.send(payload);
                        }
                    },
                    onclose() {
                        console.log('Key exchange channel closed', (isAlice ? 'Alice' : 'Bob'));
                    }
                });

                // Create drive exchange channel at the same time
                const driveChannel = mux.createChannel({
                    protocol: PROTOCOLS.DRIVE_EXCHANGE,
                    onopen() {
                        console.log('Drive exchange channel opened', (isAlice ? 'Alice' : 'Bob'));
                    },
                    onclose() {
                        console.log('Drive exchange channel closed', (isAlice ? 'Alice' : 'Bob'));
                    }
                });

                // Key exchange messages
                const aliceToBox = keyExchangeChannel.addMessage({
                    encoding: c.binary,
                    onmessage: isAlice ? () => {} : (aliceData) => {
                        try {
                            console.log('Bob received Alice\'s data, processing...');
                            const receivedSalt = aliceData.slice(0, 16);
                            const aliceX = aliceData.slice(16, 48);
                            
                            const sharedSecret = this.spake2.computeSharedSecret(result.xPrivate, aliceX);
                            sessionKey = this.spake2.deriveSessionKey(false, result.X, aliceX, sharedSecret);
                            
                            console.log('Bob computed session key, sending X value back');
                            bobToAlice.send(result.X);
                        } catch (error) {
                            console.error('Bob error:', error);
                            reject(error);
                        }
                    }
                });

                const bobToAlice = keyExchangeChannel.addMessage({
                    encoding: c.binary,
                    onmessage: isAlice ? (bobX) => {
                        try {
                            console.log('Alice received Bob\'s X value, computing session key');
                            const sharedSecret = this.spake2.computeSharedSecret(result.xPrivate, bobX);
                            sessionKey = this.spake2.deriveSessionKey(true, result.X, bobX, sharedSecret);
                            console.log('Alice computed session key successfully');
                            
                            // Alice sends drive key immediately after computing session key
                            console.log('Alice encrypting and sending drive key...');
                            const encryptedDriveKey = this.encrypt(drive.key, sessionKey);
                            sendDriveKey.send(encryptedDriveKey);
                        } catch (error) {
                            console.error('Alice error:', error);
                            reject(error);
                        }
                    } : () => {}
                });

                // Drive exchange messages
                const sendDriveKey = driveChannel.addMessage({
                    encoding: c.binary,
                    onmessage: isAlice ? () => {} : (encryptedDriveKey) => {
                        try {
                            console.log('Bob received encrypted drive key, decrypting...');
                            driveKeyResult = this.decrypt(encryptedDriveKey, sessionKey);
                            console.log('Bob successfully decrypted drive key!');
                            resolve({ sessionKey, driveKey: driveKeyResult });
                        } catch (error) {
                            console.error('Bob drive key decryption error:', error);
                            reject(error);
                        }
                    }
                });

                // Open both channels
                keyExchangeChannel.open();
                driveChannel.open();

                // Alice resolves after sending drive key
                if (isAlice) {
                    setTimeout(() => {
                        if (sessionKey) {
                            resolve({ sessionKey, driveKey: null });
                        }
                    }, 2000);
                }

            } catch (error) {
                console.error('Exchange setup error:', error);
                reject(error);
            }
        });
    }

    async sendData(filePath) {
        const wormholeCode = HyperWormhole.generateWormholeCode();
        const initialTopic = this.wormholeCodeToTopic(wormholeCode);

        console.log("Your wormhole code is:", crayon.magenta(wormholeCode));
        console.log('Waiting for receiver to connect...');

        const store = await this.createTempCorestore();
        const drive = new Hyperdrive(store);

        goodbye(async () => {
            await drive.close();
            await store.close();
            await this.cleanup();
        });

        await this.calculateTotalSize(filePath);
        await drive.ready();

        const stats = await fs.stat(filePath);
        if (stats.isDirectory()) {
            await this.addDirectoryToDrive(drive, filePath, '/');
        } else {
            await this.addFileToDrive(drive, filePath, '/' + path.basename(filePath));
        }

        console.log(crayon.green('Files added to Hyperdrive.'));

        // Set up monitoring for all files
        for await (const entry of drive.list({ recursive: true })) {
            if (entry.value.blob) {
                const monitor = drive.monitor(entry.key);
                await monitor.ready();
                this.monitors.add(monitor);

                monitor.on('update', () => {
                    this.updateProgressBar('Uploading', monitor.uploadStats);
                });
            }
        }

        // Phase 1: Key exchange swarm
        const keyExchangeSwarm = new Hyperswarm({ maxPeers: 10 });
        goodbye(() => keyExchangeSwarm.destroy());

        const sessionKey = await new Promise((resolve, reject) => {
            const initialDiscovery = keyExchangeSwarm.join(initialTopic, { server: true, client: true });

            keyExchangeSwarm.once('connection', async (rawSocket) => {
                console.log(crayon.yellow('Receiver connected. Starting SPAKE2 exchange...'));

                try {
                    // Wrap with SecretStream for encryption
                    const socket = new SecretStream(true, rawSocket);

                    // Create Protomux instance
                    const mux = Protomux.from(socket);

                    // Perform combined key and drive exchange
                    const result = await this.performKeyAndDriveExchange(mux, wormholeCode, drive, true);
                    console.log('SPAKE2 and drive exchange completed.');
                    console.log(crayon.green('Drive key sent to receiver. Starting file transfer...'));

                    // Close the key exchange connection after a delay
                    setTimeout(() => {
                        socket.end();
                        initialDiscovery.destroy();
                        keyExchangeSwarm.destroy();
                        resolve(result.sessionKey);
                    }, 2000);

                } catch (error) {
                    console.error(crayon.red('Error in key exchange:'), error);
                    reject(error);
                }
            });
        });

        // Phase 2: Replication swarm (separate instance)
        const replicationSwarm = new Hyperswarm({ maxPeers: 10 });
        goodbye(() => replicationSwarm.destroy());

        return new Promise((resolve) => {
            console.log('Starting replication phase...');
            
            // Use findingPeers pattern
            const done = drive.findingPeers();
            
            replicationSwarm.on('connection', (socket) => {
                console.log(crayon.yellow('Peer connected for replication...'));
                
                // Use the official pattern
                drive.replicate(socket);
                
                // Simple completion detection - check for drive synchronization
                const checkCompletion = setInterval(() => {
                    if (drive.core.peers && drive.core.peers.length > 0) {
                        // Check if peer has downloaded the content
                        for (const peer of drive.core.peers) {
                            if (peer.remoteLength > 0) {
                                console.log(crayon.green('File transfer completed. Shutting down...'));
                                clearInterval(checkCompletion);
                                resolve();
                                break;
                            }
                        }
                    }
                }, 1000);
                
                // Timeout after 30 seconds
                setTimeout(() => {
                    clearInterval(checkCompletion);
                    console.log(crayon.green('Transfer timeout reached. Shutting down...'));
                    resolve();
                }, 30000);
            });

            replicationSwarm.join(drive.discoveryKey);
            replicationSwarm.flush().then(done, done);
            console.log(crayon.green('Ready for receiver. Waiting...'));
        });
    }

    async receiveData(wormholeCode, outputPath) {
        const initialTopic = this.wormholeCodeToTopic(wormholeCode);

        console.log(crayon.cyan('Connecting to sender...'));

        // Phase 1: Key exchange swarm
        const keyExchangeSwarm = new Hyperswarm({ maxPeers: 10 });
        goodbye(() => keyExchangeSwarm.destroy());

        let driveKey;
        try {
            driveKey = await new Promise((resolve, reject) => {
                const initialDiscovery = keyExchangeSwarm.join(initialTopic, { server: true, client: true });

                keyExchangeSwarm.once('connection', async (rawSocket) => {
                    console.log(crayon.green('Connected to sender. Starting SPAKE2 exchange...'));

                    try {
                        // Wrap with SecretStream for encryption
                        const socket = new SecretStream(false, rawSocket);

                        // Create Protomux instance
                        const mux = Protomux.from(socket);

                        // Perform combined key and drive exchange
                        const result = await this.performKeyAndDriveExchange(mux, wormholeCode, null, false);
                        const driveKey = result.driveKey;
                        console.log('SPAKE2 and drive exchange completed.');
                        console.log(crayon.green('Successfully received drive key!'));
                        console.log('Drive key:', HypercoreId.encode(driveKey));

                        // Clean up key exchange immediately
                        socket.end();
                        initialDiscovery.destroy();
                        keyExchangeSwarm.destroy();
                        resolve(driveKey);
                    } catch (error) {
                        console.error('Error in key exchange:', error);
                        reject(error);
                    }
                });

                // Add timeout for key exchange
                setTimeout(() => {
                    reject(new Error('Key exchange timeout'));
                }, 30000);
            });
        } catch (error) {
            console.error('Key exchange failed:', error);
            return;
        }

        console.log(crayon.green('Key exchange complete. Setting up replication...'));

        // Phase 2: Replication with separate swarm
        const store = await this.createTempCorestore();
        const drive = new Hyperdrive(store, driveKey);

        goodbye(async () => {
            await drive.close();
            await store.close();
            await this.cleanup();
        });

        await drive.ready();
        console.log('Drive is ready. Discovery key:', drive.discoveryKey.toString('hex'));

        const replicationSwarm = new Hyperswarm({ maxPeers: 10 });
        goodbye(() => replicationSwarm.destroy());

        // Use findingPeers pattern for proper connection handling
        const done = drive.findingPeers();

        let connected = false;
        replicationSwarm.on('connection', (socket) => {
            console.log(crayon.yellow('Connected to sender for replication...'));
            connected = true;
            // Use the official pattern
            drive.replicate(socket);
        });

        console.log('Joining replication swarm...');
        replicationSwarm.join(drive.discoveryKey);
        await replicationSwarm.flush().then(done, done);
        console.log('Swarm flushed and peers found. Waiting for replication connection...');

        // Wait for connection
        let waitCount = 0;
        while (!connected && waitCount < 15) {
            console.log(`Waiting for replication connection... (${waitCount + 1}/15)`);
            await new Promise(resolve => setTimeout(resolve, 1000));
            waitCount++;
        }

        if (!connected) {
            console.error('Failed to connect for replication');
            return;
        }

        console.log('Replication connected! Attempting to download files...');
        
        let downloadResult = null;
        try {
            downloadResult = await this.downloadDriveContents(drive, outputPath);
            console.log(crayon.green(`File transfer completed successfully! Downloaded ${downloadResult.fileCount} files (${this.formatSize(downloadResult.totalSize)})`));
        } catch (error) {
            console.error("Download failed:", error);
            console.log("Attempting to clean up and exit...");
        }

        // Cleanup with better error handling
        console.log('Starting cleanup...');
        
        // First destroy the swarm to close all connections
        try {
            replicationSwarm.destroy();
            console.log('Replication swarm destroyed');
        } catch (error) {
            console.log('Swarm destroy error (non-critical):', error.message);
        }

        // Wait a bit for connections to close cleanly
        await new Promise(resolve => setTimeout(resolve, 1000));

        // Close drive with timeout
        try {
            const driveClosePromise = drive.close();
            const timeoutPromise = new Promise((_, reject) => 
                setTimeout(() => reject(new Error('Drive close timeout')), 5000)
            );
            await Promise.race([driveClosePromise, timeoutPromise]);
            console.log('Drive closed successfully');
        } catch (error) {
            console.log('Drive close error (non-critical):', error.message);
        }

        // Close store with timeout
        try {
            const storeClosePromise = store.close();
            const timeoutPromise = new Promise((_, reject) => 
                setTimeout(() => reject(new Error('Store close timeout')), 5000)
            );
            await Promise.race([storeClosePromise, timeoutPromise]);
            console.log('Store closed successfully');
        } catch (error) {
            console.log('Store close error (non-critical):', error.message);
        }

        // Final cleanup
        try {
            await this.cleanup();
            console.log('Cleanup completed');
        } catch (error) {
            console.log('Cleanup error (non-critical):', error.message);
        }

        // Exit gracefully
        if (downloadResult) {
            console.log(crayon.green('HyperWormhole transfer completed successfully! 🎉'));
            process.exit(0);
        } else {
            console.log(crayon.red('HyperWormhole transfer failed.'));
            process.exit(1);
        }
    }

    async addFileToDrive(drive, filePath, drivePath) {
        const readStream = fsSync.createReadStream(filePath);
        const writeStream = drive.createWriteStream(drivePath);

        try {
            await pipeline(readStream, writeStream);
            console.log(crayon.green("Added file:", drivePath));
        } catch (error) {
            console.error(crayon.red("Error adding file", drivePath, ":", error));
            throw error;
        }
    }

    async addDirectoryToDrive(drive, dirPath, drivePath) {
        const entries = await fs.readdir(dirPath, { withFileTypes: true });
        for (const entry of entries) {
            const srcPath = path.join(dirPath, entry.name);
            const destPath = path.join(drivePath, entry.name);
            if (entry.isDirectory()) {
                await this.addDirectoryToDrive(drive, srcPath, destPath);
            } else {
                await this.addFileToDrive(drive, srcPath, destPath);
            }
        }
    }

    async downloadDriveContents(drive, outputPath) {
        console.log("Starting downloadDriveContents to", outputPath);
        
        // Wait for drive to have some content and be properly replicated
        console.log('Waiting for drive replication...');
        let attempts = 0;
        const maxWaitAttempts = 30; // 30 seconds total
        
        while (attempts < maxWaitAttempts) {
            try {
                // Check if we have peers and they have content
                if (drive.core.peers && drive.core.peers.length > 0) {
                    let hasRemoteContent = false;
                    for (const peer of drive.core.peers) {
                        if (peer.remoteLength > 0) {
                            hasRemoteContent = true;
                            console.log(`Peer has ${peer.remoteLength} blocks available`);
                            break;
                        }
                    }
                    
                    if (hasRemoteContent) {
                        // Try to list files - this will trigger downloading
                        const entries = [];
                        for await (const entry of drive.list({ recursive: true })) {
                            entries.push(entry);
                        }
                        
                        if (entries.length > 0) {
                            console.log(`Found ${entries.length} entries, starting download...`);
                            break;
                        }
                    }
                }
                
                console.log(`Attempt ${attempts + 1}: Waiting for replication...`);
            } catch (error) {
                console.log(`Attempt ${attempts + 1}: Error checking replication:`, error.message);
            }
            
            await new Promise(resolve => setTimeout(resolve, 1000));
            attempts++;
        }
        
        if (attempts >= maxWaitAttempts) {
            throw new Error('Timeout waiting for drive content replication');
        }

        let fileCount = 0;
        let totalSize = 0;

        for await (const entry of drive.list({ recursive: true })) {
            if (!entry.value.blob) {
                console.log("Skipping non-blob entry:", entry.key);
                continue;
            }

            fileCount++;
            console.log("Processing file", fileCount, ":", entry.key);

            const filePath = path.join(outputPath, entry.key);
            await fs.mkdir(path.dirname(filePath), { recursive: true });

            try {
                // Use drive.get() with timeout to prevent hanging
                console.log("Downloading file content...");
                
                const downloadPromise = drive.get(entry.key, { wait: true });
                const timeoutPromise = new Promise((_, reject) => 
                    setTimeout(() => reject(new Error('Download timeout')), 30000)
                );
                
                const content = await Promise.race([downloadPromise, timeoutPromise]);
                
                if (content) {
                    await fs.writeFile(filePath, content);
                    console.log("Downloaded and saved:", crayon.yellow(filePath));
                    totalSize += content.length;
                } else {
                    console.log("No content received for:", entry.key);
                }
            } catch (error) {
                console.error("Error downloading file", entry.key, ":", error);
                throw error;
            }
        }

        console.log("Download complete. Total files:", fileCount, "Total size:", totalSize, "bytes");

        if (fileCount === 0) {
            throw new Error('No files were downloaded');
        }
        
        return { fileCount, totalSize };
    }

    wormholeCodeToTopic(code) {
        return nodeCrypto.createHash('sha256').update(code).digest();
    }

    encrypt(data, key) {
        const iv = nodeCrypto.randomBytes(16);
        const cipher = nodeCrypto.createCipheriv('aes-256-gcm', key, iv);
        const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
        const tag = cipher.getAuthTag();
        return Buffer.concat([iv, tag, encrypted]);
    }

    decrypt(data, key) {
        const iv = data.slice(0, 16);
        const tag = data.slice(16, 32);
        const encrypted = data.slice(32);
        const decipher = nodeCrypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(tag);
        return Buffer.concat([decipher.update(encrypted), decipher.final()]);
    }

    static generateWormholeCode() {
        const number = Math.floor(Math.random() * 1000).toString().padStart(3, '0');
        const word1 = WORDLIST[Math.floor(Math.random() * WORDLIST.length)];
        const word2 = WORDLIST[Math.floor(Math.random() * WORDLIST.length)];
        return `${number}-${word1}-${word2}`;
    }

    async calculateTotalSize(filePath) {
        const stats = await fs.stat(filePath);
        if (stats.isDirectory()) {
            const files = await fs.readdir(filePath, { withFileTypes: true });
            for (const file of files) {
                const fullPath = path.join(filePath, file.name);
                if (file.isDirectory()) {
                    await this.calculateTotalSize(fullPath);
                } else {
                    const fileStats = await fs.stat(fullPath);
                    this.totalSize += fileStats.size;
                }
            }
        } else {
            this.totalSize = stats.size;
        }
    }

    updateProgressBar(action, stats) {
        const percentage = stats.percentage;
        const bar = '█'.repeat(percentage) + '-'.repeat(100 - percentage);
        const speed = this.formatSize(stats.speed) + '/s';
        singleLineLog(`${action}: [${bar}] ${percentage}% | ${this.formatSize(stats.monitoringBytes)} / ${this.formatSize(stats.targetBytes)} | ${speed}`);
    }

    formatSize(bytes) {
        if (typeof bytes !== 'number' || isNaN(bytes)) {
            return '0 B';
        }
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        let size = Math.abs(bytes);
        let unitIndex = 0;
        while (size >= 1024 && unitIndex < units.length - 1) {
            size /= 1024;
            unitIndex++;
        }
        return `${size.toFixed(2)} ${units[unitIndex]}`;
    }
}

function createCLI() {
    const program = new Command();

    program
        .version('1.0.0')
        .description('HyperWormhole - Secure P2P file transfer with Protomux');

    program
        .command('send <path>')
        .description('Send a file or folder')
        .option('--storage <path>', 'Storage path for Hyperdrive')
        .action(async (path, options) => {
            const wormhole = new HyperWormhole(options);
            try {
                await wormhole.sendData(path);
                process.exit(0)
            } catch (error) {
                console.error(crayon.red('Error sending data:'), error);
                process.exit(1);
            }
        });

    program
        .command('receive <key> [outputPath]')
        .description('Receive a file or folder')
        .option('--storage <path>', 'Storage path for Hyperdrive')
        .action(async (key, outputPath, options) => {
            const wormhole = new HyperWormhole(options);
            try {
                // Use current directory if no output path is specified
                const finalOutputPath = outputPath || process.cwd();
                await wormhole.receiveData(key, finalOutputPath);
            } catch (error) {
                console.error(crayon.red('Error receiving data:'), error);
                process.exit(1);
            }
        });

    return program;
}

if (require.main === module) {
    const cli = createCLI();
    cli.parse(process.argv);
}

module.exports = HyperWormhole;