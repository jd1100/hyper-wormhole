/* global Pear */
import Hyperswarm from 'hyperswarm';
import Corestore from 'corestore';
import Hyperdrive from 'hyperdrive';
import HypercoreId from 'hypercore-id-encoding';
import fs from 'fs/promises';
import fsSync from 'fs';
import path from 'path';
import { pipeline } from 'stream/promises';
import crayon from './my_modules/tiny-crayon';
import process from 'bare-process';
global.process = 'process'
import crypto from "bare-crypto"
import { x25519 } from '@noble/curves/ed25519';
import { sha256 } from './my_modules/@noble/hashes/sha256';
import { concatBytes } from '@noble/hashes/utils';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { hmac } from '@noble/hashes/hmac';
import os from 'os';

const { teardown, config, updates } = Pear;
import { stdout as singleLineLog } from './my_modules/single-line-log';
// process.stdout.isTTY = true;

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
function stringToUint8Array(str) {
    const arr = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        arr[i] = str.charCodeAt(i);
    }
    return arr;
}
async function mkdtemp(prefix) {
    const randomString = () => crypto.randomBytes(6).toString('hex');
    
    let attempts = 0;
    const maxAttempts = 10;
    
    while (attempts < maxAttempts) {
        const tempDir = path.join(prefix, randomString());
        try {
            await fs.mkdir(tempDir, { recursive: true });
            return tempDir;
        } catch (error) {
            if (error.code !== 'EEXIST') {
                throw error;
            }
            attempts++;
        }
    }
    
    throw new Error('Failed to create unique temporary directory after multiple attempts');
}

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
        const salt = crypto.randomBytes(16);
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
            stringToUint8Array("SPAKE2 Key Derivation"),
            isAlice ? X : Y,
            isAlice ? Y : X
        );
        return hmac(sha256, sharedSecret, info);
    }

    generateConfirmation(sessionKey) {
        return hmac(sha256, sessionKey, stringToUint8Array("Confirmation"));
    }

    verifyConfirmation(sessionKey, confirmation) {
        const expected = this.generateConfirmation(sessionKey);
        return crypto.timingSafeEqual(expected, confirmation);
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
        console.log("creating directory", path.join(os.tmpdir()))
        this.tempDir = await mkdtemp(path.join(os.tmpdir(), 'hyperwormhole-'));
        console.log(this.tempDir)
        return new Corestore(this.tempDir);
    }

    async cleanup() {
        for (const monitor of this.monitors) {
            await monitor.close();
        }
        this.monitors.clear();
        if (this.tempDir) {
            await fs.rm(this.tempDir, { recursive: true, force: true });
            this.tempDir = null;
        }
    }

    async sendData(filePath) {
        const wormholeCode = HyperWormhole.generateWormholeCode();
        const initialTopic = this.wormholeCodeToTopic(wormholeCode);

        console.log(`Your wormhole code is: ${crayon.magenta(wormholeCode)}`);
        console.log('Waiting for receiver to connect...');

        const store = await this.createTempCorestore();
        const drive = new Hyperdrive(store);

        teardown(async () => {
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

        const swarm = new Hyperswarm();

        teardown(() => swarm.destroy());

        return new Promise((resolve) => {
            const initialDiscovery = swarm.join(initialTopic, { server: true, client: false });

            swarm.once('connection', async (socket) => {
                console.log(crayon.yellow('Receiver connected. Starting SPAKE2 exchange...'));

                try {
                    const { key: passwordHash, salt } = this.spake2.hashPassword(wormholeCode);
                    const aliceKeyPair = this.spake2.generateKeyPair();
                    const aliceResult = this.spake2.computeX(true, aliceKeyPair.privateKey, passwordHash);

                    socket.write(Buffer.concat([salt, aliceResult.X]));
                    const bobData = await new Promise(resolve => socket.once('data', resolve));
                    const bobX = bobData.slice(0, 32);

                    const sharedSecret = this.spake2.computeSharedSecret(aliceResult.xPrivate, bobX);
                    const sessionKey = this.spake2.deriveSessionKey(true, aliceResult.X, bobX, sharedSecret);

                    console.log('SPAKE2 exchange completed.');

                    socket.write(drive.key);

                    console.log(crayon.green('Drive key sent to receiver. Starting file transfer...'));

                    socket.end();
                    initialDiscovery.destroy();

                    swarm.join(drive.discoveryKey);
                    swarm.on('connection', (peerSocket) => {
                        console.log(crayon.yellow('Peer connected. Starting replication...'));
                        drive.replicate(peerSocket);

                        peerSocket.on('data', (data) => {
                            if (data.toString() === 'TRANSFER_COMPLETE') {
                                console.log(crayon.green('File transfer completed. Shutting down...'));
                                resolve();
                            }
                        });
                    });

                    drive.core.on('append', () => {
                        this.transferredSize = drive.core.byteLength;
                        this.updateProgressBar('Uploading');
                    });

                    await swarm.flush();
                    console.log(crayon.green('Ready for receiver. Waiting...'));
                } catch (error) {
                    console.error(crayon.red('Error in sendData:'), error);
                    resolve();
                }
            });
        });
    }

    async receiveData(wormholeCode, outputPath) {
        const initialTopic = this.wormholeCodeToTopic(wormholeCode);

        console.log(crayon.cyan('Connecting to sender...'));

        const swarm = new Hyperswarm();

        teardown(() => swarm.destroy());

        const driveKey = await new Promise((resolve, reject) => {
            const initialDiscovery = swarm.join(initialTopic, { server: false, client: true });

            swarm.once('connection', async (socket) => {
                console.log(crayon.green('Connected to sender. Starting SPAKE2 exchange...'));

                try {
                    const aliceData = await new Promise(resolve => socket.once('data', resolve));
                    const salt = aliceData.slice(0, 16);
                    const aliceX = aliceData.slice(16, 48);

                    const { key: passwordHash } = this.spake2.hashPassword(wormholeCode);
                    const bobKeyPair = this.spake2.generateKeyPair();
                    const bobResult = this.spake2.computeX(false, bobKeyPair.privateKey, passwordHash);

                    socket.write(bobResult.X);

                    const sharedSecret = this.spake2.computeSharedSecret(bobResult.xPrivate, aliceX);
                    const sessionKey = this.spake2.deriveSessionKey(false, bobResult.X, aliceX, sharedSecret);

                    console.log('SPAKE2 exchange completed.');

                    const driveKey = await new Promise(resolve => socket.once('data', resolve));

                    console.log(crayon.green('Received drive key. Starting file transfer...'));
                    console.log('Drive key:', HypercoreId.encode(driveKey));

                    socket.end();
                    initialDiscovery.destroy();
                    resolve(driveKey);
                } catch (error) {
                    reject(error);
                }
            });
        });

        const store = await this.createTempCorestore();
        const drive = new Hyperdrive(store, driveKey);

        teardown(async () => {
            await drive.close();
            await store.close();
            await this.cleanup();
        });

        await drive.ready();
        console.log('Drive is ready. Starting download...');

        this.totalSize = 0;
        this.transferredSize = 0;

        swarm.join(drive.discoveryKey);
        let senderSocket;
        swarm.on('connection', (socket) => {
            console.log(crayon.yellow('Connected to sender. Starting replication...'));
            drive.replicate(socket);
            senderSocket = socket;
        });

        await swarm.flush();

        console.log(crayon.green('Waiting for files...'));

        try {
            await this.downloadDriveContents(drive, outputPath);
        } catch {
            console.log("Something wrong happened with file download");
        }

        console.log(crayon.green('File transfer completed'));

        if (senderSocket) {
            senderSocket.write('TRANSFER_COMPLETE');
        }

        swarm.destroy();
    }

    async addFileToDrive(drive, filePath, drivePath) {
        const readStream = fsSync.createReadStream(filePath);
        const writeStream = drive.createWriteStream(drivePath);

        try {
            await pipeline(readStream, writeStream);
            console.log(crayon.green(`Added file: ${drivePath}`));
        } catch (error) {
            console.error(crayon.red(`Error adding file ${drivePath}:`, error));
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
        for await (const entry of drive.list({ recursive: true })) {
            if (!entry.value.blob) continue;

            const monitor = drive.monitor(entry.key);
            await monitor.ready();
            this.monitors.add(monitor);

            monitor.on('update', () => {
                this.updateProgressBar('Downloading', monitor.downloadStats);
            });

            const filePath = path.join(outputPath, entry.key);
            await fs.mkdir(path.dirname(filePath), { recursive: true });

            try {
                const readStream = drive.createReadStream(entry.key);
                const writeStream = fsSync.createWriteStream(filePath);

                await pipeline(readStream, writeStream);

                console.log(`Downloaded and saved: ${crayon.yellow(filePath)}`);
            } catch (error) {
                console.error(`Error downloading file ${entry.key}:`, error);
                await fs.unlink(filePath).catch(() => {});
            }
        }
    }

    wormholeCodeToTopic(code) {
        return sha256(stringToUint8Array(code));
    }

    encrypt(data, key) {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
        const tag = cipher.getAuthTag();
        return Buffer.concat([iv, tag, encrypted]);
    }

    decrypt(data, key) {
        const iv = data.slice(0, 16);
        const tag = data.slice(16, 32);
        const encrypted = data.slice(32);
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
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

// Process command-line arguments using Pear.config.args
const args = config.args.slice();

if (args.length < 1) {
    console.error('Usage: send <path> | receive <key> [outputPath]');
} else {
    const command = args.shift();

    if (command === 'send') {
        const filePath = args.shift();
        if (!filePath) {
            console.error('Usage: send <path>');
        } else {
            const options = {}; // Process any options from args
            const wormhole = new HyperWormhole(options);
            try {
                await wormhole.sendData(filePath);
                process.exit(0)
            } catch (error) {
                console.error(crayon.red('Error sending data:'), error);
            }
        }
    } else if (command === 'receive') {
        const key = args.shift();
        const outputPath = args.shift() || process.cwd();
        const options = {}; // Process any options from args
        const wormhole = new HyperWormhole(options);
        try {
            await wormhole.receiveData(key, outputPath);
        } catch (error) {
            console.error(crayon.red('Error receiving data:'), error);
        }
    } else {
        console.error('Unknown command:', command);
        console.error('Usage: send <path> | receive <key> [outputPath]');
    }
}

